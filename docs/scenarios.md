# Scenarios

A **scenario** is a named, runnable demonstration of one ACDP behavior. Each
scenario lives in `playground/scenarios/catalog/`, exports a `ScenarioDef` plus
an async `run(spec, events)` coroutine, and is auto-discovered at import time by
`playground/scenarios/registry.py`.

## The catalog

| ID | Name | What it shows | Identity | LLM | CP | Needs | Degrades |
|----|------|---------------|----------|-----|----|-------|----------|
| `s1_single_publish` | Single Publish | Smallest publish round-trip | `did:key` | yes | — | registry-a | no |
| `s2_producer_consumer` | Producer → Consumer | One derivation edge | `did:key` | yes | — | registry-a | no |
| `s3_fanout` | Fan-out (1 → N) | One source, parallel facet analyses | `did:key` | yes | — | registry-a | no |
| `s4_chain` | Linear Chain A → B → C | C derives from both A and B | `did:key` | yes | — | registry-a | no |
| `s5_cross_registry` | Cross-Registry Chain | Edge crosses registry-a → registry-b | `did:key` | yes | — | both registries | no |
| `s6_restricted` | Restricted Visibility (V2 auth) | Audience-gated reads by three authenticated agents | `did:key` | yes | — | registry-a + live tokens | yes |
| `s7_supersession` | Supersession (v1 → v2) | Same lineage, two versions | `did:key` | yes | — | registry-a | no |
| `s8_cross_org` | Cross-Org Isolation | Two orgs, no cross-references | `did:key` | yes | — | both registries | no |
| `s9_p256_publish` | ECDSA-P256 Publish | P-256 signer + verifier parity | `did:key` (P-256) | no | — | core offline; registry-a for the round-trip | no |
| `s10_tenant_isolation` | Tenant Isolation | JWT-bound tenancy; cross-tenant denied | `did:web` (factory default) | yes | — | registry-a + live tokens | yes |
| `s11_revocation` | Token Revocation | Mint → use → revoke (RFC 7009) | `did:key` | yes | optional | registry-a + live tokens | yes |
| `s12_key_rotation` | Key Rotation + Admin Reload | Overlapping pinned-key validity windows | `did:web` (pinned) | no | optional | none (offline) | no |
| `s13_policy_deny` | Policy / Authz Enforcement | Guarded CP endpoint denies/admits | none (admin bearer) | no | required | control plane | yes |
| `s14_domain_pack` | Domain-Pack Gating | Context-type gating on ingest | none (synthetic `did:web` event) | no | required | control plane | yes |
| `s15_supersession_lineage` | Supersession w/ expected_lineage_id | `expected_lineage_id` concurrency guard | `did:key` | no | — | registry-a | no |
| `s16_dataref_ssrf` | Consumer SSRF guard (data_refs) | `data_refs[].location` fetch screened | none | no | — | none (offline) | no |
| `s17_supersession_authz` | Supersession authorization | Non-owner lineage takeover rejected | `did:key` | no | — | registry-a | yes |
| `s18_idempotency` | Idempotent publish | Repeated `Idempotency-Key` replays one context | `did:key` | no | — | registry-a | yes |
| `s19_cp_did_web_p256` | CP did:web P-256 conformance | P-256 verification method the CP resolves | `did:web` (P-256, offline) | no | — | none (offline) | no |
| `s20_reserved_tenant` | Reserved-tenant rejection | Asserting the `default` tenant is rejected | none | no | — | none (offline) | no |
| `s21_capabilities_p256` | CP capability P-256 declaration | `ecdsa-p256` capability declaration accepted | `did:web` (P-256, offline) | no | — | none (offline) | no |
| `s22_receipts` | Registry Receipts (happy path) | Registry-signed receipt verified under a Require policy | `did:key` | no | — | registry-a | yes |
| `s23_receipt_tamper` | Receipt Tamper (fail-closed) | Every missing/mutated/mismatched receipt fails closed | `did:web` (factory default, offline) | no | — | none (offline) | only with no receipt seed |
| `s24_historical_key` | Historical Key Verification | Pre-rotation context is HistoricallyAuthorized via the receipt + retained key | `did:web` (pinned) | no | — | registry-a | yes |
| `s25_did_key` | did:key Ephemeral Agents | Ephemeral agents self-verify offline; rotation is a new identity | `did:key` | no | — | registry-a | yes |
| `s26_divergence` | Divergence Diagnostics | `explain_hash_mismatch` names the JCS divergence cause | `did:key` | no | — | registry-a | yes |
| `s27_receipt_key_rotation` | Registry Receipt-Key Rotation | A historical receipt verifies under the retired receipt key | `did:key` | no | — | registry-a | yes |
| `s28_lifecycle_retraction` | Lifecycle Events & Retraction | Signed retract/republish (mark-not-delete); 409 on conflicting transitions | `did:key` | no | — | registry-a | yes |
| `s29_transparency_log` | Transparency Log Proofs | Checkpoint, inclusion and consistency proofs; tampered proofs fail closed | `did:key` | no | — | registry-a | yes |
| `s30_head_receipt_freshness` | Lineage-Head Receipt Freshness | `/current` answers are registry-signed; `as_of` freshness policy | `did:key` | no | — | registry-a | yes |
| `s31_witness_cosigning` | Transparency-Log Witness Cosigning | Independent witness cosigns a checkpoint; consumer checks the quorum | `did:key` | no | — | registry-a | yes |
| `s32_key_revocation` | Producer Key-Revocation Signal | Time-scoped key-compromise signal; pre/post-compromise classification | `did:key` live; `did:web` offline core | no | — | registry-a | yes |
| `s33_anchors` | External Anchors | Anchors are signed like any field and never dereferenced | `did:key` | no | — | registry-a | yes |
| `s34_embedded_content` | Embedded Content Integrity | `embedded.content_hash` verified over the decoded bytes | `did:key` | no | — | registry-a | yes |

How to read the columns:

- **Identity** is the DID method of the scenario's signing agents. `did:key` is
  self-certifying, so the registry can verify it without fetching anything.
  "factory default" means the scenario calls `producer_for` or
  `make_langchain_agent` without `method=`, which gives a per-run `did:web`.
  "pinned" means a fixed `did:web` whose keys are pinned in the registry config.
  S27 and S29–S32 also model the registry's own receipt key as
  `did:web:{authority}` in their offline cores.
- **LLM** is whether the run calls the configured LLM (`AgentTask` through
  `agent.run`, or `call_llm`). Only S1–S8, S10 and S11 do; `LLM_PROVIDER=mock`
  keeps them offline.
- **CP** is whether the run talks to the control plane. *Required* means the run
  degrades without `CONTROL_PLANE_URL`; *optional* means a best-effort extra
  (S11 marks a CP introspection, S12 triggers a pinned-key reload) that is
  skipped when no CP or admin token is set.
- **Needs** is the infrastructure a full live run uses. "Live tokens" means the
  registry must issue bearer tokens to the agents.
- **Degrades** is whether the run can set `degraded: true` in its summary
  instead of failing when that infrastructure is missing.

## Scenario waves

The catalog grew in waves that track remediation/feature work across the
sibling repos. The RFCs cited below are indexed in the spec's
[`rfcs/README.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/README.md):

- **V1 (S1–S8)**: core protocol: publish, derive, fan-out, chains,
  cross-registry routing, restricted visibility, supersession, cross-org
  isolation. Every agent signs with `did:key` and calls the LLM. S1–S5, S7 and
  S8 publish without a bearer token. **S6** uses three authenticated `did:key`
  agents (producer, audience member, outsider) and degrades when live token
  issuance is unavailable.
- **V2 (S9–S15)**: multi-algorithm signing (P-256), multi-tenancy, token
  revocation, key-rotation windows, policy, domain packs. **S9** verifies its
  P-256 crypto offline and skips the registry round-trip when registry-a is
  absent. **S15** publishes and supersedes a `did:key` context on registry-a.
  **S10** and **S11** need live token issuance. S10 uses per-run `did:web`
  agents and degrades against a stock registry; S11 uses `did:key` and completes
  live. **S12** evaluates rotation windows offline and reloads pinned keys at the
  CP only when one is configured. **S13** and **S14** need the control plane and
  degrade without it.
- **Round 2 (S16–S17)**: security remediation. **S16** is fully offline (injected
  DNS resolver) and proves the consumer SSRF guard blocks IMDS / mixed-answer /
  cross-port-redirect / non-https `data_refs` fetches. **S17** drives the live
  registry's producer-ownership check on supersession. Its live probe covers
  ownership only; the cross-tenant rejection has the same wire shape and is
  asserted in the unit suite.
- **Round 3 (S18–S19)**: wire conformance. **S18** proves a repeated
  `Idempotency-Key` replays a single context. **S19** is fully offline and proves
  the P-256 agent emits exactly the JWK-only `JsonWebKey2020` verification method
  the CP's `did:web` resolver accepts.
- **Round 4 (S20–S21)**: **S20** (fully offline) proves the reserved `default`
  tenant can never be *asserted* (it would alias the untenanted bucket); the
  registry returns 400 `schema_violation`, the CP 403 `not_authorized`, and the
  playground mirrors the rule client-side. **S21** (fully offline) proves the
  P-256 agent emits the `ecdsa-p256` capability declaration the CP's capability
  DTO now accepts.
- **ACDP 0.2 trust & hardening (S22–S27)**: registry receipts and the
  [RFC-ACDP-0010](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0010-registry-receipts.md) §9 key lifecycle. **S22** verifies a registry-signed receipt
  end-to-end; **S23** proves every dishonest receipt fails closed; **S24** and
  **S27** cover the §9 retired-key lifecycle, the *producer* side and the
  *registry receipt-key* side respectively, delegating resolution to the SDK's
  `receipt_key_for_algorithm` (a retired-but-retained key resolves
  `historical=true`; a removed key fails closed). **S25** exercises ephemeral
  did:key agents; **S26** uses the `explain_hash_mismatch` diagnostic API. The
  deterministic crypto cores run fully offline; the live receipt round-trips
  degrade gracefully against a stock registry. S23 is offline end to end and
  degrades only if `RECEIPT_SIGNING_SEED_B64` is blanked, because the settings
  ship a built-in default seed.
- **ACDP 0.3.0 (S28–S30)**: lifecycle, head receipts, transparency log
  ([RFC-ACDP-0011](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0011-lineage-head-receipts.md), [0012](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0012-transparency-log.md), [0013](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0013-lifecycle-events.md)), served live by registry-a's three new profiles.
  **S28** retracts and republishes a context with producer-signed lifecycle
  events (`verify_lifecycle_event`, replay/tamper fail-closed, the §7.1
  order-based derivation, 409 `invalid_lifecycle_transition` on a double
  retract). **S29** verifies the registry's Merkle log: signed checkpoint,
  inclusion of a leaf **rebuilt from the verified receipt** (`build_log_leaf`
  + `verify_log_inclusion`), and a consistency proof against the consumer's
  retained root (`verify_log_consistency`); every tampered artifact fails
  `invalid_log_proof`. **S30** verifies the signed `lineage_head_receipt` on
  `/current` (`verify_lineage_head_receipt`): head bindings across a
  supersession, `as_of` clock-skew, and the stale-is-policy freshness flag.
  Each mints its artifacts offline with the SDK primitives
  (`playground/scenarios/_receipts.py`) so the deterministic cores run with
  no registry; the live halves degrade gracefully.
- **ACDP 0.4 (S31)**: transparency-log witness cosigning
  ([RFC-ACDP-0015](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0015-witness-cosigning.md)).
  The playground acts as an independent `did:key` witness: it checks a signed
  checkpoint, cosigns it, and a consumer verifies the cosignature and a
  witness quorum, while a cosignature over a tampered root fails closed. The
  live half cosigns registry-a's real `/log/checkpoint`.
- **ACDP 0.3.0 key revocation (S32)**: the producer key-revocation signal
  ([RFC-ACDP-0014](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0014-key-revocation.md)).
  The offline core rotates a `did:web` producer from K1 to K2, revokes K1 from a
  compromise time T, and shows a K1-signed context is accepted only when its
  receipt-attested `created_at` predates T. The live half publishes a real
  `key-revocation` context to registry-a with `did:key` agents.
- **ACDP 0.5.0 (S33)**: external anchors
  ([RFC-ACDP-0016](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0016-external-anchors.md)).
  S33 shows an `anchors` entry is signed like any other field, that verification
  never dereferences `anchors[].uri` (checked inside a DNS trap), and that a
  tampered anchor fails closed. The live half supersedes an anchored context to
  show anchors carry forward unless `clear_anchors=True`.
- **Embedded data-ref content (S34)**: the `data_refs[].embedded` branch
  ([RFC-ACDP-0002](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0002-context-body.md) §6.3/§6.6), which earlier scenarios skip by
  publishing only `location`-form refs. S34 checks `embedded.content_hash` over
  the *decoded* bytes of each encoding (`json`, `utf8`, `base64`), shows it is
  independent of the DataRef-root `content_hash`, and shows a tampered byte fails
  closed on both the publish and retrieval paths. The live half round-trips and
  supersedes the refs on registry-a, degrading gracefully.

## Graceful degradation

Scenarios with *yes* in the **Degrades** column (S6, S10, S11, S13, S14, S17,
S18, S22–S34) complete even without their full infrastructure. They set
`degraded: true` in the `RunResult.summary` and exercise their deterministic
core offline (receipts, lifecycle, log proofs, tenant-header policy,
`Retry-After`). S23 sets the flag only when no receipt seed is configured. S9
(P-256 crypto) and S12 (rotation windows) follow the same complete-offline
pattern without setting the flag: their optional live halves are simply
reported as skipped. The auth-dependent paths are validated against a mocked
registry/CP in the unit suite.

Live token issuance itself works for the `did:key` scenarios (S6, S11). Only
**S10** still authenticates per-run `did:web` agents, so it is the one scenario
that degrades on token issuance against a stock registry; see the
[live auth caveat](deployment.md#live-auth-caveat).

## Anatomy of a scenario

Each catalog module exports two symbols. This is S1, lightly trimmed:

```python
# playground/scenarios/catalog/s1_single_publish.py
from playground.agents.base import AgentTask
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.scenarios.models import (
    LineageGraph, LineageNode, RunResult, RunSpec, ScenarioDef,
)

SCENARIO = ScenarioDef(
    id="s1_single_publish",
    name="Single Publish",
    description="One agent publishes one context. Smallest possible round-trip "
    "through the SDK + registry.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "quarterly cash flow"},
)


async def run(spec: RunSpec, events) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    try:
        agent = make_langchain_agent(
            spec, events, bundle, slug="solo", registry="a", method="did:key"
        )
        out = await agent.run(
            AgentTask(
                prompt=f"Summarize three notable trends in {topic} in 4 sentences.",
                title=f"{topic} — notable trends",
                context_type="data_snapshot",
                domain="finance",
                tags=["trends", "summary"],
            )
        )
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            contexts=[out.ctx_id],
            lineage_graph=LineageGraph(
                nodes=[LineageNode(ctx_id=out.ctx_id, agent_id=agent.agent_did, ...)],
                edges=[],
            ),
            summary={"agent": agent.agent_did, "ctx_id": out.ctx_id},
        )
    finally:
        await bundle.aclose()
```

### Authoring helpers (`scenarios/_factory.py`)

| Helper | Purpose |
|--------|---------|
| `did_for(authority, slug)` | `did:web:{authority}:agents:{slug}` |
| `key_id_for(authority, slug)` | `{did}#key-1` |
| `producer_for(spec, slug, authority, *, algorithm="ed25519", method="did:web")` | Deterministic Ed25519 / P-256 producer from `spec.agent_seed(slug)`; `method="did:key"` derives the DID from the key instead of `did_for` |
| `AgentBundle(settings, run_id)` | Per-run cache of `AcdpClient`s keyed by `(registry, did, tenant, mode)`; provides `client(...)` and cross-registry `authority_map(...)` |
| `make_langchain_agent(spec, events, bundle, *, slug, registry="a", authenticated=False, algorithm="ed25519", method="did:web", tenant_id=None, ...)` | Build a LangChain agent bound to a producer; `authenticated=True` attaches a token manager |

The `method` default is `did:web`, but the playground's `*.playground.local`
authorities aren't web-hosted, so a scenario that needs live token issuance
should pass `method="did:key"`.

### The data model (`scenarios/models.py`)

- **`ScenarioDef`**: static metadata: `id`, `name`, `description`,
  `registry_mode` (`single`/`dual`/`cross_org`), `agent_count`, `framework`,
  `default_inputs`, and the bound `run` coroutine.
- **`RunSpec`**: per-invocation state: `run_id`, `scenario_id`, `inputs`,
  `registry_mode`, plus `agent_seed(slug)` for deterministic identity.
- **`RunResult`**: summary returned to the API caller: `run_id`,
  `scenario_id`, `status` (`complete`/`failed`), `contexts` (ctx ids),
  `lineage_graph`, `summary` (free-form, carries `degraded`), `error`.
- **`LineageGraph`**: `nodes` (`LineageNode`: ctx_id, agent_id, title,
  context_type, registry_authority, step) and `edges` (`LineageEdge`: src, dst).
  This is what renders the derivation graph in the UI.

## Adding a new scenario

1. Create `playground/scenarios/catalog/sNN_my_scenario.py`.
2. Export a `SCENARIO: ScenarioDef` and an async `run(spec, events) -> RunResult`.
3. Use `_factory` helpers to mint agents and clients, so identity determinism and
   token wiring stay consistent. Some protocol-level scenarios deliberately go
   lower: S22, S25 and S27–S33 build producers with
   `AcdpProducer.from_seed_did_key(spec.agent_seed(slug))`, and S20, S22, S23
   and S27–S32 construct `AcdpClient` directly. Follow that pattern only when the
   scenario needs that control.
4. Emit meaningful `StepEvent`s (agents do this automatically for ACDP actions;
   use `scenario.note` events for narration).
5. Build a `LineageGraph` so the run renders.
6. The scenario is auto-discovered, so no registration is needed. Do add its id
   to the `EXPECTED` set in `tests/test_scenarios_catalog.py` so the catalog test
   fails if it ever stops loading.
7. Add a smoke/unit check under `tests/` (see
   [Testing & conformance](testing-and-conformance.md)).
