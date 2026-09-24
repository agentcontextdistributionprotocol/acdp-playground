# Testing & conformance

The playground has three test layers, increasing in fidelity:

1. **Smoke test** — `scripts/smoke_test.py` — fast offline wiring checks
2. **Unit suite** — `tests/` — offline, asserts against `httpx.MockTransport`
3. **Live conformance** — `tests/live/` + `playground/conformance.py` — probes a
   real running stack to catch mock drift

## Smoke test

```bash
make smoke        # offline
make smoke-live   # offline + live probes against make up-full
```

`scripts/smoke_test.py` runs ~14 offline checks: scenario-catalog load, SDK
round-trip (`AcdpProducer`/`AcdpVerifier`), the agent publish path against a fake
client, webhook-signature validation, control-plane forwarding, P-256 round-trip,
JCS number stability, extended body fields, JCS numeric vectors, the SSRF guard,
supersession error parse, idempotent replay, typed wire errors, and the
reserved-tenant guard. `--live` additionally runs the conformance probes.

## Unit suite

```bash
make test         # uv run pytest -q
make cov          # same suite + the coverage gate CI enforces (≥ 80%)
```

Fully offline — every registry/CP interaction is faked with
`httpx.MockTransport`. `pytest` defaults to `asyncio_mode = auto`. The `live`
marker is **skipped unless `ACDP_LIVE_STACK` is set**, so a plain `pytest` never
touches the network.

The suite covers the client (auth, v2 features, signing, idempotency, token
revoke, safe-http, error envelopes, retry-after, identifiers, pinned-key windows)
and the scenario catalog (v2, round-2, round-3, the s6/s20 special cases, and a
mocked end-to-end run).

Two mocked layers execute full scenario bodies offline:

- `tests/test_scenarios_mocked_registry.py` — runs the happy-path scenarios
  (S2–S5, S7, S8) against a **stateful in-process fake registry** that accepts
  SDK-signed publish requests, assigns `ctx_id`/`lineage_id`/`version`, and
  serves retrieval + lineage reads, so the real publish → resolve →
  derivative-publish flow executes. The fake models wire *shapes* only;
  protocol semantics stay with the live suite.
- `tests/test_scenarios_offline.py` — points every backend at an unreachable
  port and pins the degrade-gracefully contract plus the deterministic
  crypto/window cores of the auth-dependent and trust scenarios (S9+).

Coverage is measured with `pytest-cov` (`[tool.coverage]` in `pyproject.toml`;
the optional crewai/langgraph adapters are omitted) and CI fails under **80%**.
Live-only paths — the `playground/conformance.py` probe bodies — are expected
to stay uncovered offline; they're exercised by the live job.

### SDK surface guard

`tests/test_sdk_surface.py` pins the `acdp` SDK surface this repo calls. It is
the local equivalent of the SDK's own `bindings/interop/expected_surface.json`:
a declarative `EXPECTED_SURFACE` table mapping `"Class.method"` to the
`(required_args, total_args)` the repo was written against, asserted through
`inspect.signature` on the installed wheel.

**Why it exists.** `acdp` is a maturin/pyo3 extension and the playground's only
hard dependency. Python has no compile step, so a renamed method or a new
*required* positional argument doesn't fail a build — it raises `TypeError` at
the call site, at runtime, inside whichever scenario happens to run it. Worse,
scenarios that assert a *negative* ("the SDK must reject this tampered receipt")
used to catch bare `Exception` and score that `TypeError` as the rejection
working, so the break could stay invisible while the check silently stopped
running. Every other drift tripwire in this repo points at the registry and the
control plane; this one points at the SDK.

What it pins — seven tests, of which these five carry the contract (the other
two, `test_expected_surface_is_non_empty` and `test_missing_symbol_is_a_failure`,
guard the guard itself):

| Test | Asserts |
|------|---------|
| `test_every_called_symbol_exists` | Every pinned symbol still resolves on the installed wheel |
| `test_arity_matches_expected` | Each symbol's `(required, total)` arity is unchanged (one parametrized case per symbol, so the failure names the symbol) |
| `test_unresolvable_arity_is_a_failure_not_a_skip` | A symbol `inspect.signature` can't read **fails**; the guard never silently disables itself |
| `test_every_sdk_call_in_the_repo_is_registered` | A source sweep for `Acdp<Class>.<member>` across `acdp_client/`, `playground/`, `tests/` and `scripts/` — so the guard's coverage is enforced, not trusted |
| `test_pinned_attributes_stay_attributes` | Each pinned *attribute* is still non-callable — see below |

The table has a second half. pyo3 **getters** (`producer.agent_did`,
`public_key_b64`, `key_id`, `public_key_jwk`, `public_key_sec1_b64`) carry no
`__text_signature__`, so they cannot be pinned by arity at all. They live in
`EXPECTED_ATTRIBUTES` and are pinned two ways instead: they must still resolve,
and they must still be **non-callable**. That second assertion is the
load-bearing one — if a getter ever became a method, `hasattr` would stay true
while every call site reading it as a value silently started handing around a
bound method.

Arities count `self` for instance methods (`inspect.signature` on the unbound
descriptor sees it), so `AcdpProducer.sign_challenge` is `(2, 2)`.

**Updating it on an SDK bump.** Raise the `acdp>=` pin in `pyproject.toml`,
`uv lock`, then run `uv run pytest tests/test_sdk_surface.py`. A red entry is a
work item, not a number to edit: read the new signature, fix the call sites, and
move the entry last. Editing `EXPECTED_SURFACE` without touching the callers
re-hides exactly the break the guard exists to surface. A new SDK call added to
the repo needs a new entry — `test_every_sdk_call_in_the_repo_is_registered`
will tell you so by name.

### Narrow rejection guard

`playground/scenarios/_sdk_guard.py` is the runtime half of the same problem.
Scenarios that assert the SDK refuses something route through
`expect_rejection(fn)` / `run_guarded(fn)`, which accept only the failures the
bindings can actually express — `RuntimeError`, `ValueError`, and the four typed
exceptions (`InvalidLogProof`, `ImmutableField`, `InvalidLifecycleTransition`,
`InvalidWitnessCosignature`). `TypeError` propagates, so a call-convention break
surfaces as a loud run error instead of a false "failed closed". Its contract is
pinned by `tests/test_sdk_guard.py`.

This applies **only** to handlers that turn a raise into a *positive* assertion.
The catalog's remaining broad `except Exception` handlers guard blocks that
perform I/O: they absorb transport failure so a run degrades gracefully instead
of hard-failing, and narrowing them would break the degrade-gracefully contract.

### Synthetic-identifier sweep

`acdp_client.identifiers` mints every synthetic `ctx_id` / `lineage_id` the repo
uses — `synthetic_ctx_id(authority, seed)` is deterministic and produces a real
identifier: the `acdp://` scheme, a lowercase DNS authority, and a v4 UUID with
correct version *and* variant nibbles. `tests/test_identifiers.py` then sweeps
`playground/`, `tests/`, `scripts/` and `docs/` for scheme-prefixed literals and
fails on any that the grammar rejects.

**Why a sweep and not just a helper.** The SDK only began *parsing* identifiers
strictly in 0.14.x. Before that, fixtures shaped like `acdp://r/1` sat green for
releases — a conformance harness asserting against ids no registry could ever
assign. The sweep is what stops one growing back.

| Test | Asserts |
|------|---------|
| `test_no_nonconformant_ctx_id_literals_in_repo` | Every swept literal is conformant or allowlisted with a stated reason |
| `test_no_acdp_literals_in_the_scenario_catalog` | The catalog holds **no** scheme literals at all — even a conformant one is a future drift site; scenarios mint ids, they never spell them |
| `test_intentionally_malformed_allowlist_entries_are_actually_malformed` | The allowlist can't launder a real mistake: every "deliberately malformed" entry must genuinely fail the grammar |
| `test_not_an_id_input_allowlist_entries_state_a_reason` | Every entry in the second category carries a reason |

The allowlist has exactly two categories and nothing else: `INTENTIONALLY_MALFORMED`
(negative fixtures a test asserts are *rejected*) and `NOT_AN_ID_INPUT` (strings
nothing ever parses — signed webhook payload bytes, a documentation ellipsis, a
`<uuid>` grammar template). Adding a third category, or an entry with no reason,
is how the guard stops guarding.

## Live conformance

A mock can drift from the real binary (the reserved-tenant `422 → 400` fix is
the cautionary tale). The **live suite** re-checks the externally-observable
contracts against a running `make up-full` stack.

```bash
make up-full          # in another shell
make test-live        # ACDP_LIVE_STACK=1 pytest -m live
make smoke-live       # scripts/smoke_test.py --live
```

The probes live in `playground/conformance.py`, in three ordered groups shared
by both entry points.

**Registry core** (`REGISTRY_PROBES`):

| Probe | Asserts |
|-------|---------|
| `probe_reserved_tenant_400` | `X-Tenant-Id: default` → **400** `schema_violation` |
| `probe_error_envelope_content_type` | A 404 returns `application/acdp+json` with a parseable error code |
| `probe_ingest_body_limit_413` | A >1 MiB body → **413** before parsing |
| `probe_receipts_profile_advertised` | `acdp-registry-receipts` is advertised and `acdp_version` is at or above the probe's floor (a *minimum*, not an allowlist — the registry's version legitimately climbs as RFCs land) |
| `probe_did_key_method_advertised` | `did:key` appears in `supported_did_methods` — the gate the ephemeral-agent scenarios publish through |
| `probe_served_ctx_id_binding` | A retrieval serves back the **same** `ctx_id` it was asked for, on both `/contexts/{id}` and `/contexts/{id}/body` (RFC-ACDP-0006 §4.1 step 7) |
| `probe_media_type_gate` | `POST /contexts` gates on `Content-Type` per RFC-ACDP-0007 §4.1 — `text/plain` → **415** `unsupported_media_type`, a `charset` parameter accepted, an absent header accepted *on this route* |
| `probe_interim_revocation_type_rejected` | A new publish typed `acdp:key-revocation` → **400** `schema_violation` (RFC-ACDP-0014 §10 retirement) |
| `probe_anchors_require_0_5_0` | A publish carrying `anchors` while declaring `acdp_version` below 0.5.0 → **400** `schema_violation` (RFC-ACDP-0016 §14) |

**0.3.0 endpoint contracts** (`ENDPOINT_0_3_0_PROBES`, RFC-ACDP-0011/0012/0013):

| Probe | Asserts |
|-------|---------|
| `probe_log_checkpoint_signed` | `GET /log/checkpoint` returns a signed `acdp-log/1` tree head |
| `probe_log_proof_inclusion_and_consistency` | `GET /log/proof` serves both proof shapes, including the §9.1 step-4 `tree_size` binding to the embedded checkpoint |
| `probe_head_receipt_on_current` | `GET /lineages/{id}/current` carries a signed `acdp-lhr/1` `lineage_head_receipt` bound to its lineage |
| `probe_retract_endpoint_fails_closed` | `POST /contexts/{id}/retract` refuses a stranger's signed retract with the ACDP envelope — never a 2xx, never a bare route miss |

**Control plane** (`CONTROL_PLANE_PROBES`):

| Probe | Asserts |
|-------|---------|
| `probe_cp_events_cap` | `GET /events` caps `limit` server-side (CP #51) |
| `probe_cp_revocations_shape` | `GET /auth/revocations` → `{entries, next_cursor}` |
| `probe_cp_pinned_keys_reload` | `POST /admin/pinned-keys/reload` accepts the admin bearer |
| `probe_capability_algorithm_accepted` | The capability DTO accepts `ecdsa-p256` (CP #51) |

### Skip vs. fail

A probe may return a "skipped" summary **only** when the surface it tests is
genuinely optional for the registry in front of it — an unadvertised profile, or
a spec line below the one that introduced the rule. Everything else is a
failure. In particular, a registry that answers **201 where a gate should answer
400 fails the probe**; "this build doesn't implement it" is the finding, not an
excuse to skip.

### Served-`ctx_id` binding

`probe_served_ctx_id_binding` is the live half of a check the client now
enforces on *every* retrieval (see
[Served-`ctx_id` binding](client-sdk.md#served-ctx_id-binding-rfc-acdp-0006-41-step-7)).
It publishes a deterministic `did:key` context, reads it back, and asserts the
served `body.ctx_id` equals the requested one. It passes against a conforming
registry — which is the point: if the real binary ever stopped honouring the
binding, every playground run would start failing with `CtxIdBindingError`, and
this probe is what says which side is at fault. Its offline counterpart in
`tests/test_conformance_probes.py` serves a *substituted* body through
`MockTransport` and asserts the probe fails, so the probe cannot quietly become
a no-op.

### The three registry-contract probes

These pin contracts the siblings enforce today that no scenario would notice
regressing — each one's *observable* behaviour in the playground is identical
whether the gate exists or not.

- **`probe_media_type_gate`** is deliberately two-sided. `AcdpClient` labels
  every request `application/json`, so a registry that narrowed its accept-set
  to `application/acdp+json` alone would break every publish, retract and
  republish at once — and a reject-only probe would stay green straight
  through it. So the probe asserts the rejection (`text/plain` → 415
  `unsupported_media_type`, checked on the **envelope code**, not the status
  alone, so a proxy answering 415 can't be mistaken for a conformant registry)
  *and* both accept cases. The header-less accept is scoped to `POST /contexts`
  and must not be generalized: that route infers a type for a body with no
  `Content-Type`, while `/auth/*` rejects one with 415 — a per-route divergence
  the registry documents and intends. Its two accept-side publishes share one
  `Idempotency-Key`, so the probe adds at most one context to the registry
  however often it runs.
- **`probe_interim_revocation_type_rejected`** pins the RFC-ACDP-0014 §10
  *retirement* of the interim `acdp:key-revocation` context type. S32 publishes
  the modern `key-revocation` spelling, so the playground would notice nothing
  if a registry started accepting the interim form again. The probe publishes a
  schema-**valid** revocation body under the interim type on purpose: a
  malformed one answered 400 `schema_violation` long before §10 existed, so a
  broken body would pass green against a registry with no retirement gate at
  all. For the same reason it requires the message to name the offending type —
  `schema_violation` is the generic body-rejection code and can't say which rule
  fired. Scoped to registries advertising 0.5.0 or above; below that line §10
  requires the interim form to be treated as an opaque custom type and
  *accepted*.
- **`probe_anchors_require_0_5_0`** pins the RFC-ACDP-0016 §14 gate S33 depends
  on: `anchors` carried under a declared `acdp_version` below 0.5.0 is refused.
  S33 only ever publishes the accepted side. No version scoping is needed — on
  an older registry the other half of the same gate (§10, the registry's own
  advertised version) refuses the publish with the same status and code.

Each has a `MockTransport` counterpart in `tests/test_conformance_probes.py`
that serves the *wrong* answer and asserts the probe raises, so none of them can
decay into a check that passes against any registry at all.

The live probes are **skipped unless `ACDP_LIVE_STACK` is set** (their
`MockTransport` counterparts above are not — those run on every plain
`pytest`). The SSE de-duplication
check additionally needs `ACDP_LIVE_SSE=1` (the bug only reproduces on a Redis
`StreamHub`; the demo stack is memory-backed). CI runs the live suite on manual
`workflow_dispatch` **and on a weekly schedule** (Mondays 05:17 UTC) — the
schedule is the mock-drift tripwire.

## Linting & formatting

```bash
make lint     # ruff check
make fmt      # ruff format
```

`ruff` is configured in `pyproject.toml` (line length 100, target `py312`).
CI enforces both `ruff check` **and** `ruff format --check` — run `make fmt`
before pushing.

## What CI runs

`.github/workflows/ci.yml`, per event:

| Job | When | What |
|-----|------|------|
| `test` | push / PR | `ruff check` + `ruff format --check`, pytest with the 80% coverage gate, smoke test — on Python **3.12 and 3.13** |
| `docker` | PR | Builds the playground image (no push) so a broken `Dockerfile` can't hide until the next release tag; shares the release workflow's layer cache |
| `live` | `workflow_dispatch` / weekly schedule | Boots registry-a + control-plane from the sibling repos and runs `pytest -m live` + `smoke_test.py --live`; uploads compose logs as an artifact on failure |

Superseded pushes to the same PR cancel the in-flight run. Dependency bumps
arrive weekly via Dependabot (`uv` lockfile + GitHub Actions, grouped; the
`acdp` SDK pin is excluded — bumping it is a by-hand semantic change).

## Helper scripts

| Script | Purpose |
|--------|---------|
| `scripts/smoke_test.py` | Offline wiring checks; `--live` adds conformance probes |
| `scripts/gen_keys.py` | Deterministic agent identity material — `--algorithm ed25519\|ecdsa-p256 <authority> <slug>...` emits `public_key_b64` / SEC1 / JWK / `verificationMethod` |
| `scripts/pinned_keys_diff.py` | Translate registry `[playground.pinned_keys]` TOML → CP `CONTROL_PLANE_PINNED_KEYS` env; `--diff` exits 2 on drift; `--format json` for JSON |
| `scripts/detailed_demo.py` | A richer end-to-end demo driver |

### Pinned-key diff workflow

```bash
# Emit the CP env var for a registry's pinned keys
python scripts/pinned_keys_diff.py config/registry-a.toml

# Fail (exit 2) if it differs from the current CONTROL_PLANE_PINNED_KEYS env
python scripts/pinned_keys_diff.py --diff config/registry-a.toml
```

Token format is `did=pubkey[:algorithm[:validFrom..validUntil]]` — a default-alg,
no-window key is just `did=pubkey` for backward compatibility.
