# acdp-playground

The ACDP playground generates real protocol traffic so the SDK
(`acdp-rs`), the registry (`acdp-registry-rs`), and the control plane
(`acdp-control-plane`) can be exercised end-to-end. It spins agents, calls
real LLMs (in 10 of the 34 scenarios), publishes signed context, streams
events over SSE, and forwards registry webhooks.

## Documentation

Full docs live in [`docs/`](docs/) and are published as the **/playground**
section of [agentcontextdistributionprotocol.io](https://agentcontextdistributionprotocol.io):

| Doc | Covers |
|-----|--------|
| [Getting started](docs/getting-started.md) | Install, smoke-test, run the stack, first run |
| [Architecture](docs/architecture.md) | Components, request flow, the run lifecycle, the SSE bus |
| [Scenarios](docs/scenarios.md) | The S1–S34 catalog and how to author one |
| [HTTP API](docs/http-api.md) | Every route on the playground service |
| [Client library](docs/client-sdk.md) | `acdp_client` — the async wrapper the playground drives the SDK through |
| [Agents](docs/agents.md) | `BasePlaygroundAgent` + LangChain / CrewAI / LangGraph |
| [Configuration](docs/configuration.md) | The playground's own environment variables |
| [Deployment](docs/deployment.md) | Docker Compose, the full stack, Railway |
| [Testing & conformance](docs/testing-and-conformance.md) | Smoke test, unit suite, live probes, opt-in real-LLM suite, CI |

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
    catalog/                  # S1–S34 — auto-discovered, runnable end-to-end
  api/                        # FastAPI routers: health, scenarios, runs, contexts, webhooks
  config.py                   # pydantic-settings (.env)
  events.py                   # in-process SSE bus
  control_plane.py            # no-op when CONTROL_PLANE_URL unset
scripts/
  smoke_test.py               # offline wiring checks (P-256, JCS vectors, SSRF guard, CP stub); --live adds real-stack conformance
  gen_keys.py                 # deterministic agent identity material (ed25519 / p256)
  pinned_keys_diff.py         # translate registry [[playground.pinned_keys]] → CONTROL_PLANE_PINNED_KEYS env
config/                       # registry-a.toml, registry-b.toml
docker-compose.yml            # playground + two registries
docker-compose.full.yml       # overlay adding db (Postgres) + control plane + ui-console (make up-full)
tests/                        # offline unit suite; tests/live/ = opt-in live-stack suites
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

| ID | Name | What it shows | Identity | LLM | CP | Degrades |
|----|------|---------------|----------|-----|----|----------|
| `s1_single_publish` | Single Publish | Smallest publish round-trip | `did:key` | yes | — | no |
| `s2_producer_consumer` | Producer → Consumer | One derivation edge | `did:key` | yes | — | no |
| `s3_fanout` | Fan-out (1 → N) | One source, parallel facet analyses | `did:key` | yes | — | no |
| `s4_chain` | Linear Chain A → B → C | C derives from both A and B | `did:key` | yes | — | no |
| `s5_cross_registry` | Cross-Registry Chain | Edge crosses registry-a → registry-b | `did:key` | yes | — | no |
| `s6_restricted` | Restricted Visibility (V2 auth) | Audience-gated reads by three authenticated agents | `did:key` | yes | — | yes |
| `s7_supersession` | Supersession (v1 → v2) | Same lineage, two versions | `did:key` | yes | — | no |
| `s8_cross_org` | Cross-Org Isolation | Two orgs, no cross-references | `did:key` | yes | — | no |
| `s9_p256_publish` | ECDSA-P256 Publish | P-256 signer + verifier parity | `did:key` (P-256) | no | — | no |
| `s10_tenant_isolation` | Tenant Isolation | JWT-bound tenancy; cross-tenant denied | `did:web` (per run) | yes | — | yes |
| `s11_revocation` | Token Revocation | Mint → use → revoke (RFC 7009) | `did:key` | yes | optional | yes |
| `s12_key_rotation` | Key Rotation + Admin Reload | Overlapping pinned-key validity windows | `did:web` (pinned) | no | optional | no |
| `s13_policy_deny` | Policy / Authz Enforcement | Guarded CP endpoint denies/admits | none | no | required | yes |
| `s14_domain_pack` | Domain-Pack Gating | Context-type gating on ingest | none | no | required | yes |
| `s15_supersession_lineage` | Supersession w/ expected_lineage_id | `expected_lineage_id` concurrency guard | `did:key` | no | — | no |
| `s16_dataref_ssrf` | Consumer SSRF guard (data_refs) | `data_refs[].location` fetch screened (offline) | none | no | — | no |
| `s17_supersession_authz` | Supersession authorization | Non-owner lineage takeover rejected | `did:key` | no | — | yes |
| `s18_idempotency` | Idempotent publish | Repeated `Idempotency-Key` replays one context | `did:key` | no | — | yes |
| `s19_cp_did_web_p256` | CP did:web P-256 conformance | P-256 verification method the CP now resolves (offline) | `did:web` (P-256) | no | — | no |
| `s20_reserved_tenant` | Reserved-tenant rejection | Asserting the `default` tenant is rejected (offline) | none | no | — | no |
| `s21_capabilities_p256` | CP capability P-256 declaration | `ecdsa-p256` capability declaration accepted (offline) | `did:web` (P-256) | no | — | no |
| `s22_receipts` | Registry Receipts (happy path) | Registry-signed receipt verified under a Require policy | `did:key` | no | — | yes |
| `s23_receipt_tamper` | Receipt Tamper (fail-closed) | Every missing/mutated/mismatched receipt fails closed (offline) | `did:web` (per run) | no | — | only with no receipt seed |
| `s24_historical_key` | Historical Key Verification | Pre-rotation context is HistoricallyAuthorized via receipt + retained key | `did:web` (pinned) | no | — | yes |
| `s25_did_key` | did:key Ephemeral Agents | Ephemeral agents self-verify offline; rotation is a new identity | `did:key` | no | — | yes |
| `s26_divergence` | Divergence Diagnostics | `explain_hash_mismatch` names the JCS divergence cause | `did:key` | no | — | yes |
| `s27_receipt_key_rotation` | Registry Receipt-Key Rotation | Registry rotates its receipt key; a historical receipt still verifies | `did:key` | no | — | yes |
| `s28_lifecycle_retraction` | Lifecycle Events & Retraction | Signed retract/republish (mark-not-delete); 409 on conflicting transitions | `did:key` | no | — | yes |
| `s29_transparency_log` | Transparency Log Proofs | Signed checkpoint + inclusion + consistency proofs; tamper fails closed | `did:key` | no | — | yes |
| `s30_head_receipt_freshness` | Lineage-Head Receipt Freshness | `/current` answers are registry-signed; `as_of` freshness/stale policy | `did:key` | no | — | yes |
| `s31_witness_cosigning` | Transparency-Log Witness Cosigning | Independent witness cosigns a checkpoint; consumer verifies quorum | `did:key` | no | — | yes |
| `s32_key_revocation` | Producer Key-Revocation Signal | Time-scoped key-compromise signal; pre/post-compromise classification | `did:key` live, `did:web` offline core | no | — | yes |
| `s33_anchors` | External Anchors | Anchors are signed like any field and never dereferenced | `did:key` | no | — | yes |
| `s34_embedded_content` | Embedded Content Integrity | `embedded.content_hash` verified over the decoded bytes | `did:key` | no | — | yes |

**Identity** is the signing agents' DID method (`did:web` per run comes from the
factory default; pinned keys live in the registry config). **LLM** marks the
10 scenarios that call the configured LLM. **CP** *required* means the run
degrades without a control plane; *optional* means a best-effort extra.
**Degrades** means the run completes with `degraded: true` in its summary when
its infrastructure is missing. [`docs/scenarios.md`](docs/scenarios.md) has the
full table, including the infrastructure each scenario needs.

> **V2 scenarios (S9–S15)** exercise the features that landed across the
> sibling repos: P-256 signing, multi-tenancy, token revocation,
> key-rotation windows, policy, and domain packs. **S9** verifies its P-256
> crypto offline and skips the registry round-trip when registry-a is absent;
> **S15** runs against registry-a in the default stack. **S10** and **S11** need
> live token issuance; S10's per-run `did:web` agents degrade against a stock
> registry, while S11's `did:key` agent completes live. **S12** runs offline and
> only reloads pinned keys when a control plane is configured. **S13** and
> **S14** need the control plane and **degrade gracefully** (marked
> *complete-but-degraded* via a `degraded: true` summary flag) without it; see
> *Running the full stack*.
>
> **Round-2 scenarios (S16–S17)** cover the latest security-remediation
> wave. **S16** runs **fully offline** (injected DNS resolver) and proves
> the consumer SSRF guard blocks IMDS / mixed-answer / cross-port-redirect
> / non-https `data_refs` fetches. **S17** drives the live registry's
> producer-ownership check on supersession and degrades gracefully without
> it; the cross-tenant variant is asserted in the unit suite.
>
> **Round-3 scenarios (S18–S19)** cover the post-remediation wire
> conformance. **S18** proves a repeated `Idempotency-Key` replays a single
> context (degrades gracefully). **S19** runs **fully offline** and proves
> the playground's P-256 agent emits exactly the JWK-only `JsonWebKey2020`
> verification method the control plane's did:web resolver now accepts.
>
> **Round-4 scenario (S20)** tracks `acdp-control-plane` #50. **S20** runs
> **fully offline** and proves the reserved `default` tenant can never be
> *asserted* (via `X-Tenant-Id` or a token claim), since it would alias the
> untenanted bucket. The registry returns 400 `schema_violation` and the CP
> 403 `not_authorized`; the playground mirrors the rule client-side so a
> caller fails fast locally.
>
> **S21** tracks `acdp-control-plane` #51. **S21** runs **fully offline** and
> proves the playground's P-256 agent emits the `ecdsa-p256` capability
> declaration the control plane's capability DTO now accepts (it previously
> rejected P-256 at the validation boundary); the signature is self-verified
> against the producer's key.
>
> **ACDP 0.2 trust & hardening (S22–S27)** cover registry receipts and the
> [RFC-ACDP-0010](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0010-registry-receipts.md) §9 key lifecycle: a registry-signed receipt on every publish
> (**S22**), every dishonest receipt failing closed (**S23**), the retired-key
> lifecycle on both the producer (**S24**) and registry receipt-key (**S27**)
> sides, ephemeral did:key agents (**S25**), and the `explain_hash_mismatch`
> diagnostic (**S26**). Deterministic cores run fully offline; live receipt
> round-trips degrade gracefully against a stock registry.
>
> **ACDP 0.3.0 (S28–S30)** cover lifecycle events & retraction
> ([RFC-ACDP-0013](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0013-lifecycle-events.md), **S28**), the registry's Merkle transparency log
> ([RFC-ACDP-0012](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0012-transparency-log.md), **S29**), and signed lineage-head receipts on `/current`
> ([RFC-ACDP-0011](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0011-lineage-head-receipts.md), **S30**), all served live by registry-a's receipts/
> lifecycle/log profiles. Each mints its artifacts offline with the SDK
> primitives, so the deterministic core runs with no registry; the live
> halves degrade gracefully.
>
> **S31** proves transparency-log witness cosigning
> ([RFC-ACDP-0015](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0015-witness-cosigning.md)):
> the playground acts as an independent `did:key` witness, and a cosignature
> over a tampered root fails closed.
>
> **S32** proves the producer key-revocation signal
> ([RFC-ACDP-0014](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0014-key-revocation.md)):
> a K1-signed context is accepted only when its receipt-attested `created_at`
> predates the compromise time. The offline core uses a `did:web` producer; the
> live half publishes with `did:key` agents.
>
> **S33** proves external anchors
> ([RFC-ACDP-0016](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0016-external-anchors.md)):
> an anchor is signed like any other field, is never dereferenced by
> verification, and carries forward on supersede unless `clear_anchors=True`.
>
> **S34** proves **embedded data-ref content integrity**
> ([RFC-ACDP-0002](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0002-context-body.md) §6.3/§6.6): `embedded.content_hash` is
> checked over the *decoded* bytes of each encoding (`json`, `utf8`,
> `base64`), is independent of the DataRef-root `content_hash`, and a tampered
> byte fails closed on both the publish and retrieval paths. The live half
> round-trips the refs through registry-a, degrading gracefully without one.

## Protocol features exercised

Beyond the scenario catalog, the client layer (`acdp_client`) drives the
protocol surfaces a real consumer needs: Ed25519 and ECDSA-P256 signing,
JWT-bound multi-tenancy (`X-Tenant-Id` only as a fallback), cursor pagination
(`search_all`), token revocation, pinned-key rotation windows, idempotent
publish, the consumer SSRF guard for `data_refs` fetches, and the
`application/acdp+json` error envelope surfaced as typed exceptions
(`NotAuthorizedError`, `PayloadTooLargeError`, `SupersededError`,
`CursorError`). Signing, JCS canonicalization and SSRF classification are
delegated to the SDK — the playground keeps only the host-language
orchestration. [`docs/client-sdk.md`](docs/client-sdk.md) documents what the
client adds; the rules themselves live in
[RFC-ACDP-0007](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0007-capabilities.md)
(capabilities and error envelope),
[RFC-ACDP-0008](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0008-security.md)
(security, tenancy, SSRF) and the SDK's
[security.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md)
and [errors.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/errors.md).
The history of how each piece landed is in [`CHANGELOG.md`](CHANGELOG.md).

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
make up-full   # playground + registry-a + registry-b + db + control-plane + ui-console
```

`docker-compose.full.yml` adds the NestJS control plane on `:3001`, the
ephemeral Postgres `db` (`postgres:16-alpine` on `tmpfs`) it requires for its
event, run and receipt-audit stores, and the UI console on `:3000`. It points
the playground at the control plane and wires the shared HMAC + admin secrets
(auth nonces and revocations stay in memory, `AUTH_PERSISTENCE=memory`). S13 and S14 need the control plane
(S11 and S12 use it optionally); the full stack gives them a real one.

> **Live auth caveat.** For a `did:web` agent, the registry verifies
> challenge signatures by resolving the agent's DID document. The
> playground's `*.playground.local` DIDs aren't web-hosted and keys rotate
> per run, so token issuance for per-run `did:web` agents can't complete
> against a stock registry. That affects **S10 only**: the other
> token-issuing scenarios (S6, S11) use self-certifying `did:key` agents and
> complete live. S10 **degrades gracefully** and is validated by the unit
> suite (mocked registry/CP); the deterministic cores (P-256 crypto, cursor
> logic, tenant-header policy, rotation windows, Retry-After) are fully
> exercised offline.

### Live conformance suite

The unit suite and `smoke_test` assert against `httpx.MockTransport` — fast and
offline, but a mock can drift from the real binary (the reserved-tenant
`422 → 400` fix is the cautionary tale). The **live suite** re-checks the
externally-observable contracts against a running `make up-full` stack:

```bash
make up-full                     # in another shell (or: docker compose ... up -d --wait)
make test-live                   # ACDP_LIVE_STACK=1 uv run pytest -m live -q
make smoke-live                  # scripts/smoke_test.py --live
```

The 18 probes live in `playground/conformance.py` (shared by both entry
points), grouped into registry-core contracts, the 0.3.0 endpoint set, and the
control plane. They cover the reserved-tenant 400, the `application/acdp+json`
error envelope, the 1 MiB ingest 413, the receipts profile and minimum
`acdp_version` being advertised, `did:key` being an advertised DID method, the
served-`ctx_id` binding, the media-type gate on `POST /contexts`, the retired
interim revocation type, the anchors version gate, rejection of a
self-signed key revocation, signed log checkpoints with inclusion and
consistency proofs, head receipts on `/current`, the retract endpoint failing
closed, the `GET /events` server-side limit cap, the revocation-feed shape, the
admin pinned-key reload, and that the capability DTO accepts `ecdsa-p256`
(CP #51). [`docs/testing-and-conformance.md`](docs/testing-and-conformance.md)
lists each one and what it asserts.

Everything in `tests/live/` is **skipped unless `ACDP_LIVE_STACK` is set**, so a
plain `pytest` stays offline. Two files need a second gate as well, so
`make test-live` collects but skips them: the SSE de-duplication check
(`ACDP_LIVE_SSE=1`; the bug only reproduces on a Redis StreamHub, and the demo
stack is memory-backed) and the opt-in **real-LLM suite**
(`ACDP_LIVE_REAL_LLM=1`), which runs all 34 scenarios through `POST /runs`
against the playground at `PLAYGROUND_URL` with a real, billed provider key and
re-verifies every context they publish. CI runs the conformance probes on
manual `workflow_dispatch` and on a weekly schedule, as the tripwire for exactly
that kind of drift; it never runs the real-LLM suite.

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
from `../acdp-control-plane`), its Postgres `db` (stock `postgres:16-alpine`
image), and the UI console (built from `../acdp-ui-console`).

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
