# Architecture

## Big picture

The playground is a **FastAPI service** that owns the run lifecycle. A client
starts a *run* of a named *scenario*; the scenario drives one or more *agents*;
each agent calls an LLM and publishes signed context to a *registry*; the
registry verifies and stores it, then fires a *webhook* back to the playground;
the playground fans every protocol step out to the client over **SSE**.

```
                    ┌──────────────────────────────────────────────┐
   client  ──POST /runs──▶  playground (FastAPI)                    │
      ▲                     │                                        │
      │  SSE                │  scenario.run(spec, events)            │
      │ /runs/{id}/events   ▼                                        │
      └──────────────  in-process SSE bus  ◀── webhook.received ──┐  │
                            │                                     │  │
                            ▼  agent.publish / retrieve / search  │  │
                     ┌──────────────┐   webhook   ┌───────────────┴┐ │
                     │ acdp_client  │────────────▶│ registry-a/-b/ │ │
                     │ (async httpx)│◀────────────│ -c (Rust bins) │ │
                     └──────┬───────┘   POST /ctx └───────┬────────┘ │
                            │ sign via acdp (Rust SDK)    │          │
                            ▼                              ▼          │
                     forward webhooks ───────────▶  control-plane ───┘
                     run start/complete            (optional, NestJS)
```

## Components

### The playground service (`playground/`)

| Module | Responsibility |
|--------|----------------|
| `main.py` | FastAPI app, CORS, router wiring, lifespan |
| `config.py` | `pydantic-settings` over `.env`; `get_settings()` is `lru_cache`d |
| `api/` | HTTP routers: `health`, `scenarios`, `runs`, `contexts`, `webhooks` |
| `scenarios/` | Scenario registry, run lifecycle, and the S1–S33 catalog |
| `agents/` | `BasePlaygroundAgent` + LangChain / CrewAI / LangGraph adapters |
| `events.py` | In-process SSE bus — one `asyncio.Queue` per run |
| `control_plane.py` | Optional fire-and-forget bridge to the control plane |
| `conformance.py` | Live conformance probes against real binaries |
| `pinned_keys.py` | Key-rotation window evaluation (RFC-ACDP-0008 §9.3) |
| `retry_after.py` | RFC 9110 `Retry-After` parsing (re-export) |
| `logging_setup.py` | `pretty` / `json` structured logging |

### The client library (`acdp_client/`)

An async `httpx` + Pydantic layer over the `acdp` Rust SDK. It owns transport
and type marshaling; **all cryptography, JCS canonicalization, and SSRF IP
classification are delegated to the Rust SDK**. See [Client SDK](client-sdk.md).

### The SDK (`acdp`, published to PyPI from `acdp-rs/bindings/acdp-py`)

A compiled (maturin/pyo3) extension — installed as a prebuilt wheel from PyPI —
that the playground imports for every protocol
primitive — signers (`AcdpProducer` / `AcdpP256Producer`), the verifier, the JCS
canonicalizer, the SSRF policy, and the `did:web` resolver. The playground does
**not** reimplement any of these; it only orchestrates them. The SDK is its own
project — see
[`acdp-rs`](https://github.com/agentcontextdistributionprotocol/acdp-rs/tree/main/docs)
([producing](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/producing.md),
[consuming](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/consuming.md),
[security](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md),
[bindings](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/bindings.md)).

## The run lifecycle

1. **`POST /runs`** (`api/runs.py`) validates the scenario, generates a UUID
   `run_id`, merges scenario defaults with request inputs into a `RunSpec`,
   creates an event queue (`events.create_queue`), and spawns
   `runner.execute(...)` as a background task. Returns **202** with a
   `stream_url`.

2. **`runner.execute`** (`scenarios/runner.py`) emits `run.started` and
   notifies the control plane of the start, calls the scenario's
   `run(spec, events)` coroutine, then emits `run.complete` (with
   `contexts_produced` and the `lineage_graph`) or `run.error` (with the
   exception message; the full traceback is kept on the persisted
   `RunResult.error`). The `RunResult` is persisted in an in-process dict and a
   `notify_run_complete` is fired to the control plane.

3. **The scenario** uses `_factory.py` helpers to mint deterministic agent
   identities, build `AcdpClient`s (one per registry, cached in an
   `AgentBundle`), and run agents. Each agent action (`publish`, `retrieve`,
   `search`) emits a `StepEvent` onto the queue.

4. **The registry** verifies the signature, stores the context, and (in a fully
   live deployment) POSTs a webhook to `/webhooks/acdp`. The webhook handler
   verifies the HMAC signature, lifts tenant/dedup/run headers onto the event,
   transforms it into a `StepEvent`, and enqueues it onto the matching run's bus.

5. **`GET /runs/{id}/events`** drains the queue as `text/event-stream`, emitting
   keepalives every 15s and terminating on `run.complete` / `run.error`. If the
   run already finished, it replays the final result instead.

## Determinism & identity

Agent identities are **deterministic within a run** but **fresh across runs**.
`RunSpec.agent_seed(slug)` is `sha256(run_id:slug)`, so the same slug always
yields the same 32-byte key seed within a run, while a new `run_id` produces a
new identity. Producers are minted from these seeds in `_factory.producer_for`
(P-256 rehashes the seed to a valid curve scalar). DIDs follow
`did:web:{authority}:agents:{slug}` with key id `{did}#key-1`.

## Graceful degradation

Many V2/security scenarios depend on infrastructure that a stock registry can't
fully provide offline (live token issuance needs web-hosted `did:web`
documents; some checks need the control plane). These scenarios are built to
**degrade gracefully** — they complete and mark themselves *complete-but-degraded*
via a `degraded: true` flag in the run summary rather than failing. Their
deterministic cores (P-256 crypto, cursor logic, tenant-header policy, rotation
windows, `Retry-After`) are always exercised offline. See
[Scenarios](scenarios.md) for which scenarios degrade.

## The control plane bridge

This describes the **playground side** of the integration. The control plane is
its own project — its ingest, auth, introspection, revocation, and policy
surfaces are documented in
[`acdp-control-plane`](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/tree/main/docs)
([API.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/API.md),
[INGEST.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/INGEST.md),
[AUTH.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/AUTH.md)).

When `CONTROL_PLANE_URL` is empty the playground runs standalone and every
forwarding method is a no-op. When set:

- Every registry webhook is **HMAC-signed with the CP secret** and forwarded to
  `/ingest/acdp`, preserving the `X-ACDP-Event-Id` dedup key and stamping
  `X-Tenant-Id` for tenant attribution.
- Run **start/complete** notifications are posted.
- The bridge honors a cooperative `Retry-After` on transient upstream
  responses (`429/502/503/504`) with one capped retry.

When `CONTROL_PLANE_ADMIN_TOKEN` is set, `ControlPlaneClient` also drives the CP
operator surface: `introspect` (RFC 7662), the cross-issuer `revocations` feed,
the cross-run `events` history, capability declaration, domain-pack listing, and
`reload_pinned_keys`.
