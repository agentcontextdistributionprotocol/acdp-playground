# Architecture

## Big picture

The playground is a **FastAPI service** that owns the run lifecycle. A client
starts a *run* of a named *scenario*; the scenario drives one or more *agents*
or producers; agents in the LLM-backed scenarios call an LLM, and every
producer publishes signed context to a *registry*; the registry verifies and
stores it and — where webhooks are enabled — fires a *webhook* back to the
playground; the playground fans every protocol step out to the client over
**SSE**.

```
                    ┌──────────────────────────────────────────────┐
   client  ──POST /runs──▶  playground (FastAPI)                    │
      ▲                     │                                        │
      │  SSE                │  scenario.run(spec, events)            │
      │ /runs/{id}/events   ▼                                        │
      └──────────────  in-process SSE bus  ◀── acdp.* (webhook) ──┐  │
                            │                                     │  │
                            ▼  agent.publish / retrieve / search  │  │
                     ┌──────────────┐   webhook   ┌───────────────┴┐ │
                     │ acdp_client  │────────────▶│ registry-a /-b │ │
                     │ (async httpx)│◀────────────│  (Rust bins)   │ │
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
| `scenarios/` | Scenario registry, run lifecycle, and the S1–S34 catalog |
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

### Scenario helpers (`playground/scenarios/_receipts.py`)

Some trust scenarios need artifacts a *registry* produces — a signed receipt,
a lifecycle event, a lineage-head receipt, a log checkpoint, or the body a
retrieval would serve — in states a live registry never emits (e.g. a receipt
under a since-rotated key). `_receipts.py` models that registry side offline
(`synthesize_retrieval_body`, `mint_receipt`, `mint_lifecycle_event`,
`mint_lineage_head_receipt`, `mint_log_checkpoint`). The delegation boundary
still holds: every signature, digest and canonicalization comes from the SDK,
and the playground authors only the registry-owned fields. What those fields
are, and which sit outside the content hash, is the spec's — see
[RFC-ACDP-0001 §5.7](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md#57-content-hash),
[RFC-ACDP-0010](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0010-registry-receipts.md)
and the registry's
[RECEIPTS.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/RECEIPTS.md).

## The run lifecycle

1. **`POST /runs`** (`api/runs.py`) validates the scenario, generates a UUID
   `run_id`, merges scenario defaults with request inputs into a `RunSpec`,
   creates an event queue (`events.create_queue`), and spawns
   `runner.execute(...)` as a background task. Returns **202** with a
   `stream_url`.

2. **`runner.execute`** (`scenarios/runner.py`) emits `run.started` and
   **awaits** the control-plane start notification (so start/complete stay
   ordered at the CP), calls the scenario's
   `run(spec, events)` coroutine, then emits `run.complete` (with
   `contexts_produced`, the `lineage_graph`, and `status`) or `run.error`
   (with the exception message and `status`; the full traceback is kept on
   the persisted `RunResult.error`). The event `type` distinguishes
   "returned" from "raised", not success from failure — a scenario can
   return without raising but with `RunResult.status == "failed"` (an
   internal assertion failing, not a transport exception), which still
   streams `run.complete`; its `status` field is what actually carries the
   outcome. The `RunResult` is persisted in an in-process dict, then
   `notify_run_complete` is awaited (the playground's `complete` is sent to the
   CP as `completed`; `failed` passes through).

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
   run already finished, it replays the final result instead. The queue is
   dropped whenever the stream ends — including a mid-run client disconnect,
   which currently makes the run 404 until its result is persisted (see
   [HTTP API](http-api.md#get-runsrun_idevents--sse) and
   [acdp-playground#92](https://github.com/agentcontextdistributionprotocol/acdp-playground/issues/92)).

## Determinism & identity

Agent identities are **deterministic within a run** but **fresh across runs**.
`RunSpec.agent_seed(slug)` is `sha256(run_id:slug)`, so the same slug always
yields the same 32-byte key seed within a run, while a new `run_id` produces a
new identity. Producers are minted from these seeds in `_factory.producer_for`
(P-256 rehashes the seed to a valid curve scalar). The DID method is chosen per
call: the factory **default** (`method="did:web"` on `producer_for` and
`make_langchain_agent`) yields `did:web:{authority}:agents:{slug}` with key id
`{did}#key-1`, but most scenarios pass `method="did:key"` — a self-certifying
DID derived from the key, which a stock registry can verify without fetching a
DID document — and several build `AcdpProducer.from_seed_did_key(...)`
directly. A few still use `did:web` (the factory default, or a DID pinned in
the registry config). [Scenarios](scenarios.md) lists the identity each
scenario uses.

## Graceful degradation

Many V2/security scenarios depend on infrastructure the stack may not provide
— the control plane, a provisioned registry profile (receipts, lifecycle, log),
or, for S10 only, live token issuance for a per-run `did:web` identity whose
DID document is not web-hosted. These scenarios are built to **degrade
gracefully** — they complete and mark themselves *complete-but-degraded* via a
`degraded: true` flag in the run summary rather than failing. Their
deterministic cores (P-256 crypto, cursor logic, tenant-header policy, rotation
windows, `Retry-After`) are always exercised offline. See
[Scenarios](scenarios.md) for which scenarios degrade and why.

## The control plane bridge

This describes only the **playground side** (`playground/control_plane.py`).
The control plane's ingest, auth, introspection, revocation, capability and
policy surfaces are its own — see
[API.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/API.md),
[INGEST.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/INGEST.md)
and [AUTH.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/AUTH.md).

- `CONTROL_PLANE_URL` empty → every method is a no-op and the playground runs
  standalone.
- Set → registry webhooks are forwarded to `/ingest/acdp` (headers and signing
  in [HTTP API → Webhooks](http-api.md#post-webhooksacdp)), and run
  start/complete are posted and awaited by the runner.
- Forwards and run notifications (`_post`) get **one** retry on
  `429/502/503/504`, and only when the response carries a parseable
  `Retry-After`; the wait is capped at 30 s. Failures are logged, never raised
  into the run.
- `domain_packs()` (`GET /domain-packs`) needs only `CONTROL_PLANE_URL`.
  `introspect`, `revocations`, `events`, `declare_capability` and
  `reload_pinned_keys` additionally need `CONTROL_PLANE_ADMIN_TOKEN` and
  return `None` without it.
