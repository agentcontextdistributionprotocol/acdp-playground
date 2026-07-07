# acdp-playground

The ACDP playground generates real protocol traffic so the SDK
(`acdp-rs`), the registry (`acdp-registry-rs`), and (later) the
control plane can be exercised end-to-end. It spins agents, calls real
LLMs, publishes context, streams events over SSE, and forwards
registry webhooks.

## Documentation

Full docs live in [`docs/`](docs/) and are published as the **/playground**
section of [agentcontextdistributionprotocol.io](https://agentcontextdistributionprotocol.io):

| Doc | Covers |
|-----|--------|
| [Getting started](docs/getting-started.md) | Install, smoke-test, run the stack, first run |
| [Architecture](docs/architecture.md) | Components, request flow, the run lifecycle, the SSE bus |
| [Scenarios](docs/scenarios.md) | The S1–S21 catalog and how to author one |
| [HTTP API](docs/http-api.md) | Every route on the playground service |
| [Client library](docs/client-sdk.md) | `acdp_client` — the async wrapper the playground drives the SDK through |
| [Agents](docs/agents.md) | `BasePlaygroundAgent` + LangChain / CrewAI / LangGraph |
| [Configuration](docs/configuration.md) | The playground's own environment variables |
| [Deployment](docs/deployment.md) | Docker Compose, the full stack, Railway |
| [Testing & conformance](docs/testing-and-conformance.md) | Unit suite, smoke test, live probes |

These docs cover **only what is unique to the playground**. Anything owned by
another project is referenced, not re-explained:

| Project | What it owns |
|---------|--------------|
| [Spec / RFCs](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/tree/main/rfcs) | The protocol: context body, publish, retrieval, discovery, cross-registry, capabilities, security |
| [`acdp-rs`](https://github.com/agentcontextdistributionprotocol/acdp-rs/tree/main/docs) | The SDK — signing, JCS canonicalization, the SSRF policy, error taxonomy, the Python/Node bindings |
| [`acdp-registry-rs`](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/tree/main/docs) | Registry HTTP API, authentication, multi-tenancy, webhooks, configuration |
| [`acdp-control-plane`](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/tree/main/docs) | Token issuance, introspection, revocation, policy, ingest, federation |

## Layout

```
acdp_client/                  # async httpx + Pydantic aliases over the acdp-py SDK
playground/
  agents/                     # BasePlaygroundAgent + LangChain/CrewAI/LangGraph
  scenarios/
    catalog/                  # S1–S5, S7, S8 — runnable end-to-end
  api/                        # FastAPI routers: scenarios, runs, contexts, webhooks
  config.py                   # pydantic-settings (.env)
  events.py                   # in-process SSE bus
  control_plane.py            # no-op when CONTROL_PLANE_URL unset
scripts/
  smoke_test.py               # offline wiring checks (P-256, JCS vectors, SSRF guard, CP stub); --live adds real-stack conformance
  gen_keys.py                 # deterministic agent identity material (ed25519 / p256)
  pinned_keys_diff.py         # translate registry [playground]pinned_keys → CONTROL_PLANE_PINNED_KEYS env
config/                       # registry-a.toml, registry-b.toml
docker-compose.yml            # playground + two registries
docker-compose.full.yml       # overlay adding the control plane (make up-full)
```

## Quickstart

```bash
# 1) Install (uses uv; resolves the acdp SDK wheel from PyPI)
make dev

# 2) Sanity check (no LLM, no registry needed)
make smoke

# 3) Run the playground + both registries
cp .env.example .env
# edit .env: set OPENAI_API_KEY=... (or LLM_PROVIDER=mock for offline runs)
make up

# 4) List scenarios
curl localhost:8000/scenarios | jq

# 5) Start a run
curl -X POST localhost:8000/runs \
    -H 'content-type: application/json' \
    -d '{"scenario_id":"s4_chain","inputs":{"topic":"GPU supply chains"}}'

# 6) Stream events (replace RUN_ID with the returned id)
curl -N localhost:8000/runs/RUN_ID/events
```

## Scenarios

| ID | Name | What it shows |
|----|------|---------------|
| `s1_single_publish` | Single Publish | Smallest publish round-trip |
| `s2_producer_consumer` | Producer → Consumer | One derivation edge |
| `s3_fanout` | Fan-out 1→N | One source, parallel facet analyses |
| `s4_chain` | Linear Chain A→B→C | C derives from both A and B |
| `s5_cross_registry` | Cross-Registry Chain | Edge crosses registry-a → registry-b |
| `s6_restricted` | Restricted Visibility | Audience-gated reads (auth) |
| `s7_supersession` | Supersession v1→v2 | Same lineage, two versions |
| `s8_cross_org` | Cross-Org Isolation | Two orgs, no cross-references |
| `s9_p256_publish` | ECDSA-P256 Publish | P-256 signer + verifier parity |
| `s10_tenant_isolation` | Tenant Isolation | JWT-bound tenancy; cross-tenant denied |
| `s11_revocation` | Token Revocation | Mint → use → revoke (RFC 7009) |
| `s12_key_rotation` | Key Rotation + Reload | Overlapping pinned-key validity windows |
| `s13_policy_deny` | Policy / Authz | Guarded CP endpoint denies/admits |
| `s14_domain_pack` | Domain-Pack Gating | Context-type gating on ingest |
| `s15_supersession_lineage` | Supersession + guard | `expected_lineage_id` concurrency guard |
| `s16_dataref_ssrf` | Consumer SSRF guard | `data_refs[].location` fetch screened (offline) |
| `s17_supersession_authz` | Supersession authz | Non-owner / cross-tenant lineage takeover rejected |
| `s18_idempotency` | Idempotent publish | Repeated `Idempotency-Key` replays one context |
| `s19_cp_did_web_p256` | CP did:web P-256 | P-256 verification method the CP now resolves (offline) |
| `s20_reserved_tenant` | Reserved-tenant guard | Asserting `default` tenant is rejected (offline) |

> **V2 scenarios (S9–S15)** exercise the features that landed across the
> sibling repos — P-256 signing, multi-tenancy, token revocation,
> key-rotation windows, policy, and domain packs. **S9** and **S15** run
> in the default stack (anonymous publish). **S10–S14** need live token
> issuance and/or the control plane; they **degrade gracefully** (marked
> *complete-but-degraded* via a `degraded: true` summary flag) when that
> infra is absent — see *Running the full stack*.
>
> **Round-2 scenarios (S16–S17)** cover the latest security-remediation
> wave. **S16** runs **fully offline** (injected DNS resolver) and proves
> the consumer SSRF guard blocks IMDS / mixed-answer / cross-port-redirect
> / non-https `data_refs` fetches. **S17** drives the live registry's
> producer-ownership check on supersession and degrades gracefully without
> it.
>
> **Round-3 scenarios (S18–S19)** cover the post-remediation wire
> conformance. **S18** proves a repeated `Idempotency-Key` replays a single
> context (degrades gracefully). **S19** runs **fully offline** and proves
> the playground's P-256 agent emits exactly the JWK-only `JsonWebKey2020`
> verification method the control plane's did:web resolver now accepts.
>
> **Round-4 scenario (S20)** tracks `acdp-control-plane` #50. **S20** runs
> **fully offline** and proves the reserved `default` tenant can never be
> *asserted* (via `X-Tenant-Id` or a token claim) — it would alias the
> untenanted bucket. The registry returns 400 `schema_violation` and the CP
> 403 `not_authorized`; the playground mirrors the rule client-side so a
> caller fails fast locally.
>
> **S21** tracks `acdp-control-plane` #51. **S21** runs **fully offline** and
> proves the playground's P-256 agent emits the `ecdsa-p256` capability
> declaration the control plane's capability DTO now accepts (it previously
> rejected P-256 at the validation boundary); the signature is self-verified
> against the producer's key.

## V2 protocol features

- **Multi-algorithm signing.** Agents sign with Ed25519 or ECDSA-P256.
  The token manager posts the matching `algorithm` to `/auth/token` and
  the verifier picks the right path. `scripts/gen_keys.py --algorithm
  ecdsa-p256` emits SEC1/JWK/`verificationMethod` material.
- **Multi-tenancy.** The authoritative tenant rides in the JWT `tenant`
  claim (issuer-stamped via the registry's `auth.tenant_agents`).
  `X-Tenant-Id` is **only a fallback** for unbound producer-signed
  publishes (RFC-ACDP-0008 §6.4); the client never lets the header
  contradict the claim.
- **Cursor pagination.** `AcdpClient.search_all(...)` walks the whole
  paginated sequence and **continues through an empty-but-cursored page**
  (RFC-ACDP-0005 §2.3). `invalid_cursor` / `cursor_expired` surface as
  `CursorError`.
- **Token revocation.** `TokenManager.revoke(...)` calls
  `POST /auth/token/revoke` (RFC 7009) and drops the cached token.
- **Pinned-key rotation.** Overlapping `valid_from`/`valid_until` windows
  let an outgoing and incoming key both verify during a rollover;
  `pinned_keys_diff.py` encodes algorithm + windows in the CP wire
  format and the CP can hot-reload via `/admin/pinned-keys/reload`.
- **Extended body fields.** Publishes carry `data_refs`, `data_period`,
  and `expires_at`; supersession uses `expected_lineage_id`.

### Round-2 sibling sync (2026-06)

Closes the security-remediation + wire-conformance gap that landed across
the siblings just after the V2 sync.

- **Consumer SSRF guard.** `acdp_client.safe_http` screens any
  `data_refs[].location` fetch the way RFC-ACDP-0008 §4.9 requires:
  https-only, **all** resolved IPs validated against private/loopback/
  IMDS/ULA/NAT64/v4-mapped ranges with **mixed-answer rejection**,
  **same-authority** (scheme+host+effective-port) redirects only, and
  size/timeout caps. `AcdpClient.fetch_data_ref(...)` also verifies the
  `content_hash`. The per-address/URL **classification is delegated to the
  Rust SDK** (`acdp.AcdpSsrfPolicy`, acdp-py 0.2.0) — the playground keeps
  only the host-language orchestration (DNS, the mixed-answer loop, the
  `httpx` fetch) because its client never goes through the Rust
  `RegistryClient`. Validated against the RFC's `*-ssrf-*` fixtures; demoed
  offline by **S16**.
- **Error wire envelope.** `AcdpHTTPError` parses the RFC-ACDP-0007 §4
  `application/acdp+json` envelope (`code`/`message`/`details`); a denied
  or non-owner supersession surfaces as `SupersededError` with a `.reason`
  (`not_found`, `cross_registry_supersession_unsupported`, …).
- **JCS canonicalization.** `acdp.AcdpCanonicalizer` (the Rust SDK, acdp-py
  0.2.0) produces the RFC 8785 §3.2.2.3 canonical form (negative-zero → `0`,
  exponential bands, integer exactness) — the wire form producers must hit.
  The playground drives it through the binding and gates it on the RFC's
  `can-011` vectors instead of shipping a second pure-Python implementation.
- **Cooperative token throttling.** `TokenManager` honours a `429 +
  Retry-After` (RFC 9110) on `/auth/challenge` and `/auth/token` with one
  capped retry — matching the registry's per-agent challenge throttle.
- **Identifier hygiene.** `acdp_client.identifiers` validates that
  `origin_registry` is a bare DNS hostname (no port/scheme/DID/uppercase),
  per RFC-ACDP-0002 §3.1.

### Round-3 sibling sync (2026-06)

Tracks the P0/P1 remediation + RFC-ACDP-0007 §5 wire-conformance wave that
landed in the registry (`#24`/`#25`/`#26`) and control plane (`#48`/`#49`)
just after round 2.

- **§5 error-code model.** `acdp_client.models.ERROR_CODES` enumerates the
  machine codes the registry now emits (`invalid_signature`,
  `unsupported_algorithm`, `key_resolution_failed`/`_unreachable`,
  `not_implemented`, …); `SIGNATURE_ERROR_CODES` groups the "re-sign / fix
  my key" subset. `data_ref_hash_mismatch` is kept **distinct** from
  `hash_mismatch` (body hash vs data-ref hash).
- **Typed wire errors.** `not_authorized` moved to **403** (`#24`) and
  surfaces as `NotAuthorizedError`; an oversized body returns **413** with
  `application/acdp+json` even from the outer middleware (`#26`) and
  surfaces as `PayloadTooLargeError`. Both subclass `AcdpHTTPError`. The
  client retries only on **401** (stale token) — a 403 is terminal.
- **Idempotent publish.** The client forwards `Idempotency-Key` verbatim
  (1–256 chars; an out-of-range value is treated as absent server-side, not
  pre-rejected); a repeat replays one context — demoed by **S18**.
- **Audience telemetry.** `CachedToken.aud` peeks the JWT `aud` claim (now
  bound to the issuing authority on both registry and CP) and logs it on
  mint, so an audience-mismatch `TokenAuthError` is diagnosable. Verification
  still belongs to the issuer — the playground only peeks.
- **CP error-envelope logging.** The control-plane bridge parses the CP's
  ACDP error envelope (`#49`) and logs `error.code`/`reason` instead of a
  bare status.
- **did:web P-256 parity.** The CP now resolves P-256 did:web verification
  methods (`#49`); **S19** proves the playground emits exactly the JWK-only
  `JsonWebKey2020` form it accepts (offline).
- **Config knobs.** `docker-compose.full.yml` + `.env.example` document the
  new CP env (`JWT_AUDIENCE`, `AUTH_REQUIRE_TENANT`, `INGEST_*`,
  `WEBHOOK_SSRF_*`) with secure-but-demo-friendly defaults; the registry
  configs note the new loopback-bind constraint.

## LLM provider

Set `LLM_PROVIDER` in `.env` to one of:

- `openai` (default) — `LLM_MODEL=gpt-4o-mini`, needs `OPENAI_API_KEY`
- `anthropic` — needs `ANTHROPIC_API_KEY`
- `mock` — deterministic offline echo (for smoke / CI runs without API keys)

## Control plane

`acdp-control-plane` is a separate sibling project — now fully
implemented with bearer-token issuance, RFC 7662 introspection,
RFC 7009 revocation, federated cross-issuer validation, multi-tenancy,
policy engine, and an append-only audit ledger.

When `CONTROL_PLANE_URL` is empty, the playground runs standalone. When
set, every registry webhook is HMAC-signed and forwarded (preserving the
`X-ACDP-Event-Id` dedup key); run start/complete notifications are also
posted there. Multi-tenant deployments set the `X-Tenant-Id` header on
forwarded webhooks so the CP attributes events to the right tenant. The
forwarder honours a cooperative `Retry-After` on a transient upstream.

The `ControlPlaneClient` also drives the CP operator surface when
`CONTROL_PLANE_ADMIN_TOKEN` is set: `introspect` (RFC 7662),
`revocations` (the cross-issuer feed), and `reload_pinned_keys`.

### Running the full stack

```bash
make up-full   # playground + registry-a + registry-b + control-plane
```

`docker-compose.full.yml` adds the NestJS control plane (DB-less:
`AUTH_PERSISTENCE=memory`) on `:3001`, points the playground at it, and
wires the shared HMAC + admin secrets. The auth/revocation/policy
scenarios (S10–S14) have a real IdP to talk to there.

> **Live auth caveat.** The registry verifies challenge signatures by
> resolving the agent's `did:web` document — the playground's
> `*.playground.local` DIDs aren't web-hosted and keys rotate per run, so
> token issuance can't fully complete against a stock registry. The
> auth-dependent scenarios are built to **degrade gracefully** and are
> validated by the unit suite (mocked registry/CP); the deterministic
> cores (P-256 crypto, cursor logic, tenant-header policy, rotation
> windows, Retry-After) are fully exercised offline.

### Live conformance suite

The unit suite and `smoke_test` assert against `httpx.MockTransport` — fast and
offline, but a mock can drift from the real binary (the reserved-tenant
`422 → 400` fix is the cautionary tale). The **live suite** re-checks the
externally-observable contracts against a running `make up-full` stack:

```bash
make up-full                     # in another shell (or: docker compose ... up -d --wait)
make test-live                   # ACDP_LIVE_STACK=1 pytest -m live
make smoke-live                  # scripts/smoke_test.py --live
```

The probes live in `playground/conformance.py` (shared by both entry points) and
cover the reserved-tenant 400, the `application/acdp+json` error envelope, the
1 MiB ingest 413, the `GET /events` server-side limit cap, the revocation-feed
shape, the admin pinned-key reload, and that the capability DTO accepts
`ecdsa-p256` (CP #51). They are **skipped unless `ACDP_LIVE_STACK` is set**, so a
plain `pytest` stays offline. The SSE de-duplication check additionally needs
`ACDP_LIVE_SSE=1` (the bug only reproduces on a Redis StreamHub; the demo stack
is memory-backed). CI runs this suite on manual `workflow_dispatch` only.

### TokenManager refresh-reason telemetry

`acdp_client.TokenManager` emits structured logs on every mint with a
`refresh_reason` field — one of `first_use`, `proactive_refresh`, or
`reactive_401` — so operators can detect abnormal patterns
(secret rotation, audience mismatch, clock skew). Logs land at INFO
on success and WARNING on failure with a `failure_kind` discriminator.

## Compose layout

The playground image builds with `context: .` — the `acdp` Python SDK
installs as a prebuilt wheel from PyPI, so no sibling checkout is needed.
The registry images build from the sibling `acdp-registry-rs/` repo's
Dockerfile; `docker-compose.full.yml` overlays the control plane (built
from `../acdp-control-plane`).

## Deploying to Railway

`.github/workflows/deploy-images.yml` builds this repo's playground image and
pushes it to `ghcr.io/<owner>/acdp-playground` on a `v*` tag or manual dispatch
(the `acdp` SDK comes from PyPI — no sibling checkout required). The other stack
images are published by their own repos. The playground image binds Railway's
dynamic `$PORT`/`$HOST`.
**See [`railway/DEPLOY.md`](railway/DEPLOY.md)** for the full deploy — service
topology, IPv6 private networking, per-service env vars, and the shared-secret
wiring.

## Local SDK development

The `acdp` Python package is a compiled (maturin/pyo3) extension published as a
wheel on PyPI, which is what `make dev` installs. To hack on the SDK against a
local `../acdp-rs` checkout (needs a Rust toolchain), overlay a source build
into the venv:

```bash
make dev-local   # uv sync + `maturin develop --release` against ../acdp-rs
make build-sdk   # re-overlay after pulling acdp-rs changes (SDK dev only)
```

`maturin develop` installs the local build over the PyPI wheel; the next plain
`uv sync` restores the published wheel. Override the checkout path with
`make build-sdk ACDP_RS=/path/to/acdp-rs`.
