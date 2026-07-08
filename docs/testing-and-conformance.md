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

## Live conformance

A mock can drift from the real binary (the reserved-tenant `422 → 400` fix is
the cautionary tale). The **live suite** re-checks the externally-observable
contracts against a running `make up-full` stack.

```bash
make up-full          # in another shell
make test-live        # ACDP_LIVE_STACK=1 pytest -m live
make smoke-live       # scripts/smoke_test.py --live
```

The probes live in `playground/conformance.py` (shared by both entry points):

| Probe | Asserts |
|-------|---------|
| `probe_reserved_tenant_400` | `X-Tenant-Id: default` → **400** `schema_violation` |
| `probe_error_envelope_content_type` | A 404 returns `application/acdp+json` with a parseable error code |
| `probe_ingest_body_limit_413` | A >1 MiB body → **413** before parsing |
| `probe_cp_events_cap` | `GET /events` caps `limit` server-side (CP #51) |
| `probe_cp_revocations_shape` | `GET /auth/revocations` → `{entries, next_cursor}` |
| `probe_cp_pinned_keys_reload` | `POST /admin/pinned-keys/reload` accepts the admin bearer |
| `probe_capability_algorithm_accepted` | The capability DTO accepts `ecdsa-p256` (CP #51) |

These are **skipped unless `ACDP_LIVE_STACK` is set**. The SSE de-duplication
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
