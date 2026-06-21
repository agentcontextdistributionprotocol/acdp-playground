# Scenarios

A **scenario** is a named, runnable demonstration of one ACDP behavior. Each
scenario lives in `playground/scenarios/catalog/`, exports a `ScenarioDef` plus
an async `run(spec, events)` coroutine, and is auto-discovered at import time by
`playground/scenarios/registry.py`.

## The catalog

| ID | Name | What it shows | Offline? |
|----|------|---------------|----------|
| `s1_single_publish` | Single Publish | Smallest publish round-trip | needs registry |
| `s2_producer_consumer` | Producer → Consumer | One derivation edge | needs registry |
| `s3_fanout` | Fan-out 1→N | One source, parallel facet analyses | needs registry |
| `s4_chain` | Linear Chain A→B→C | C derives from both A and B | needs registry |
| `s5_cross_registry` | Cross-Registry Chain | Edge crosses registry-a → registry-b | needs both registries |
| `s6_restricted` | Restricted Visibility | Audience-gated reads (auth) | needs auth |
| `s7_supersession` | Supersession v1→v2 | Same lineage, two versions | needs registry |
| `s8_cross_org` | Cross-Org Isolation | Two orgs, no cross-references | needs registry |
| `s9_p256_publish` | ECDSA-P256 Publish | P-256 signer + verifier parity | needs registry |
| `s10_tenant_isolation` | Tenant Isolation | JWT-bound tenancy; cross-tenant denied | degrades |
| `s11_revocation` | Token Revocation | Mint → use → revoke (RFC 7009) | degrades |
| `s12_key_rotation` | Key Rotation + Reload | Overlapping pinned-key validity windows | degrades |
| `s13_policy_deny` | Policy / Authz | Guarded CP endpoint denies/admits | degrades |
| `s14_domain_pack` | Domain-Pack Gating | Context-type gating on ingest | degrades |
| `s15_supersession_lineage` | Supersession + guard | `expected_lineage_id` concurrency guard | needs registry |
| `s16_dataref_ssrf` | Consumer SSRF guard | `data_refs[].location` fetch screened | **fully offline** |
| `s17_supersession_authz` | Supersession authz | Non-owner / cross-tenant takeover rejected | degrades |
| `s18_idempotency` | Idempotent publish | Repeated `Idempotency-Key` replays one context | degrades |
| `s19_cp_did_web_p256` | CP did:web P-256 | P-256 verification method the CP resolves | **fully offline** |
| `s20_reserved_tenant` | Reserved-tenant guard | Asserting `default` tenant is rejected | **fully offline** |
| `s21_capabilities_p256` | P-256 capability | `ecdsa-p256` capability declaration accepted | **fully offline** |
| `s22_receipts` | Registry Receipts | did:key publish + registry-signed receipt verified under a Require policy | degrades |
| `s23_receipt_tamper` | Receipt Tamper | Every missing/mutated/mismatched receipt fails closed | **fully offline** |
| `s24_historical_key` | Historical Key | Pre-rotation context is HistoricallyAuthorized via the receipt + retained key (§9) | degrades |
| `s25_did_key` | did:key Agents | Ephemeral did:key agents self-verify offline; rotation is a new identity | degrades |
| `s26_divergence` | Divergence Diagnostics | `explain_hash_mismatch` names the JCS divergence cause | degrades |
| `s27_receipt_key_rotation` | Receipt-Key Rotation | Registry rotates its receipt key; a historical receipt verifies under the retired key (§9) | degrades |

## Scenario waves

The catalog grew in waves that track remediation/feature work across the
sibling repos:

- **V1 (S1–S8)** — core protocol: publish, derive, fan-out, chains,
  cross-registry routing, restricted visibility, supersession, cross-org
  isolation. **S1–S8** run in the default stack with anonymous publish.
- **V2 (S9–S15)** — multi-algorithm signing (P-256), multi-tenancy, token
  revocation, key-rotation windows, policy, domain packs. **S9** and **S15** run
  in the default stack; **S10–S14** need live token issuance and/or the control
  plane and **degrade gracefully** when that infra is absent.
- **Round 2 (S16–S17)** — security remediation. **S16** is fully offline (injected
  DNS resolver) and proves the consumer SSRF guard blocks IMDS / mixed-answer /
  cross-port-redirect / non-https `data_refs` fetches. **S17** drives the live
  registry's producer-ownership check on supersession.
- **Round 3 (S18–S19)** — wire conformance. **S18** proves a repeated
  `Idempotency-Key` replays a single context. **S19** is fully offline and proves
  the P-256 agent emits exactly the JWK-only `JsonWebKey2020` verification method
  the CP's `did:web` resolver accepts.
- **Round 4 (S20–S21)** — **S20** (fully offline) proves the reserved `default`
  tenant can never be *asserted* (it would alias the untenanted bucket); the
  registry returns 400 `schema_violation`, the CP 403 `not_authorized`, and the
  playground mirrors the rule client-side. **S21** (fully offline) proves the
  P-256 agent emits the `ecdsa-p256` capability declaration the CP's capability
  DTO now accepts.
- **ACDP 0.2 trust & hardening (S22–S27)** — registry receipts and the
  RFC-ACDP-0010 §9 key lifecycle. **S22** verifies a registry-signed receipt
  end-to-end; **S23** proves every dishonest receipt fails closed; **S24** and
  **S27** cover the §9 retired-key lifecycle — the *producer* side and the
  *registry receipt-key* side respectively — delegating resolution to the SDK's
  `receipt_key_for_algorithm` (a retired-but-retained key resolves
  `historical=true`; a removed key fails closed). **S25** exercises ephemeral
  did:key agents; **S26** uses the `explain_hash_mismatch` diagnostic API. The
  deterministic crypto cores run fully offline; the live receipt round-trips
  degrade gracefully against a stock registry.

## Graceful degradation

Scenarios marked *degrades* complete even without their full infrastructure.
They set `degraded: true` in the `RunResult.summary` and exercise the
deterministic core offline (P-256 crypto, cursor logic, tenant-header policy,
rotation windows, `Retry-After`). The auth-dependent paths are validated against
a mocked registry/CP in the unit suite. See the
[live auth caveat](deployment.md#live-auth-caveat) for why a stock registry
can't fully issue tokens to the playground's per-run `did:web` agents.

## Anatomy of a scenario

Each catalog module exports two symbols:

```python
# playground/scenarios/catalog/s1_single_publish.py
from playground.scenarios.models import ScenarioDef, RunResult, RunSpec, LineageGraph, LineageNode
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.agents.base import AgentTask

SCENARIO = ScenarioDef(
    id="s1_single_publish",
    name="Single Publish",
    description="Smallest publish round-trip.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "quarterly cash flow"},
)

async def run(spec: RunSpec, events) -> RunResult:
    bundle = AgentBundle(spec, events)
    agent = make_langchain_agent(spec, events, bundle, slug="solo", registry="a")
    out = await agent.run(AgentTask(prompt=..., title=..., context_type="data_snapshot"))
    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        contexts=[out.ctx_id],
        lineage_graph=LineageGraph(nodes=[LineageNode(...)], edges=[]),
    )
```

### Authoring helpers (`scenarios/_factory.py`)

| Helper | Purpose |
|--------|---------|
| `did_for(authority, slug)` | `did:web:{authority}:agents:{slug}` |
| `key_id_for(authority, slug)` | `{did}#key-1` |
| `producer_for(spec, slug, authority, *, algorithm="ed25519")` | Deterministic Ed25519 / P-256 producer from `spec.agent_seed(slug)` |
| `AgentBundle(spec, events)` | Per-run cache of `AcdpClient`s keyed by `(registry, did, tenant, mode)`; provides `client(...)` and cross-registry `authority_map(...)` |
| `make_langchain_agent(spec, events, bundle, *, slug, registry="a", authenticated=False, algorithm="ed25519", tenant_id=None, ...)` | Build a LangChain agent bound to a producer; `authenticated=True` attaches a token manager |

### The data model (`scenarios/models.py`)

- **`ScenarioDef`** — static metadata: `id`, `name`, `description`,
  `registry_mode` (`single`/`dual`/`cross_org`), `agent_count`, `framework`,
  `default_inputs`, and the bound `run` coroutine.
- **`RunSpec`** — per-invocation state: `run_id`, `scenario_id`, `inputs`,
  `registry_mode`, plus `agent_seed(slug)` for deterministic identity.
- **`RunResult`** — summary returned to the API caller: `status`
  (`complete`/`failed`), `contexts` (ctx ids), `lineage_graph`, `summary`
  (free-form, carries `degraded`), `error`.
- **`LineageGraph`** — `nodes` (`LineageNode`: ctx_id, agent_id, title,
  context_type, registry_authority, step) and `edges` (`LineageEdge`: src, dst).
  This is what renders the derivation graph in the UI.

## Adding a new scenario

1. Create `playground/scenarios/catalog/sNN_my_scenario.py`.
2. Export a `SCENARIO: ScenarioDef` and an async `run(spec, events) -> RunResult`.
3. Use `_factory` helpers to mint agents and clients — don't construct producers
   or clients by hand, so identity determinism and token wiring stay consistent.
4. Emit meaningful `StepEvent`s (agents do this automatically for ACDP actions;
   use `scenario.note` events for narration).
5. Build a `LineageGraph` so the run renders.
6. The scenario is auto-discovered — no registration needed.
7. Add a smoke/unit check under `tests/` (see
   [Testing & conformance](testing-and-conformance.md)).
