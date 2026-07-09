# Deployment

## Docker Compose

Two compose files describe the stack:

- **`docker-compose.yml`** — the playground + three registries
- **`docker-compose.full.yml`** — an overlay adding the control plane and UI
  console (run together via `make up-full`)

The playground image builds with `context: .` (this repo) — the `acdp` SDK
installs from PyPI, so no sibling checkout is needed. The registry / control
plane / UI images each build from their own sibling repo context
(`acdp-registry-rs/`, `acdp-control-plane/`, `acdp-ui-console/`).

### Services and ports

| Service | Repo | Port | Public | Compose file |
|---------|------|------|--------|--------------|
| `playground` | acdp-playground | `8000` | yes | base |
| `registry-a` | acdp-registry-rs | `8100` | no | base |
| `registry-b` | acdp-registry-rs | `8200` | no | base |
| `registry-c` | acdp-registry-rs | `8300` | no | base |
| `db` (Postgres) | — | *(internal)* | no | full |
| `control-plane` | acdp-control-plane | `3001` | no | full |
| `ui-console` | acdp-ui-console | `3000` | yes | full |

The registries store to an **ephemeral SQLite** db on a `tmpfs` mount, so state
resets on restart. The full overlay provisions an ephemeral `db` Postgres
service (also `tmpfs`) that the control plane requires; what the CP persists
there and how it migrates is CP-owned (see the control plane's
[ARCHITECTURE.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/ARCHITECTURE.md)).

### Registry config (`config/registry-a.toml`, `-b.toml`, `-c.toml`)

These are **demo configs for the registry binary** — the registry owns the
config schema (see its
[CONFIGURATION.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/CONFIGURATION.md)).
The playground-relevant choices in them are:

- `authority` / `port` — `registry-a.playground.local:8100`,
  `registry-b.playground.local:8200`, `registry-c.playground.local:8300`
- `cross_registry_resolution = true` — lets S5 route an edge across registries
- `auth.anonymous_public_reads = true`, `require_tenant = false` (a/b) — keeps
  the legacy single-tenant scenarios (S1–S8) working with anonymous publish
- **registry-c runs the receipts profile** instead of the `[playground]` lax
  mode — the S22/S24/S27 receipt scenarios target it. What that profile commits
  the registry to (verify-every-publish, atomic receipt mint, profile
  advertisement) is registry-owned — see its
  [RECEIPTS.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/RECEIPTS.md)
- `webhook.enabled = false` — the registry's SSRF policy refuses the loopback
  `http://playground:8000` target in the demo (webhook-driven events are
  exercised in the unit suite instead)
- `[playground]` pinned keys — a demo-only block that lets the playground's
  per-run `did:web` agents publish without live DID resolution (see the
  [live auth caveat](#live-auth-caveat))

The `[[playground.pinned_keys]]` entries also demonstrate **key rotation** (the
`rotating-publisher` agent has overlapping old/new Ed25519 windows, plus a
`p256-publisher` P-256 key). `scripts/pinned_keys_diff.py` translates these into
the control plane's `CONTROL_PLANE_PINNED_KEYS` wire format.

### Secrets that must line up

| Secret | Shared between |
|--------|----------------|
| `WEBHOOK_SECRET` | registries ↔ playground (inbound webhook HMAC) |
| `CONTROL_PLANE_HMAC_SECRET` / CP `WEBHOOK_SECRET` | playground ↔ control plane (forwarded webhook HMAC) |
| `CONTROL_PLANE_ADMIN_TOKEN` / CP `AUTH_ADMIN_API_KEYS` | playground ↔ control plane (admin surface) |

## The Dockerfile

`python:3.12-slim` base. Installs `uv`, copies this repo, runs
`uv sync --frozen --extra llm` (which pulls the `acdp` wheel from PyPI — no Rust
toolchain), exposes `8000`, and launches:

```
uv run --no-sync uvicorn playground.main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
```

`--no-sync` skips a redundant re-resolve at boot (the image is pre-built);
`exec` hands signals to uvicorn for graceful shutdown; `HOST`/`PORT` are dynamic
for Railway.

## Live auth caveat

The registry verifies challenge signatures by resolving the agent's `did:web`
document. The playground's `*.playground.local` DIDs aren't web-hosted and keys
rotate per run, so token issuance **can't fully complete against a stock
registry**. The auth-dependent scenarios are built to
[**degrade gracefully**](scenarios.md#graceful-degradation) and are validated by
the unit suite (mocked registry/CP). The deterministic cores — P-256 crypto,
cursor logic, tenant-header policy, rotation windows, `Retry-After` — are fully
exercised offline. The `[playground] pinned_only = false` + pinned-key config is
what lets the demo's run-keyed agents publish without live DID resolution.

## Railway

`.github/workflows/deploy-images.yml` builds this repo's playground image and
pushes it to `ghcr.io/<owner>/acdp-playground` on a `v*` tag or manual dispatch
(the `acdp` SDK comes from PyPI, so no sibling checkout is required). The other
stack images are published by their own repos to
`ghcr.io/<owner>/acdp-{registry,control-plane,ui-console}`. The playground image
binds Railway's dynamic `$PORT`/`$HOST`.

**Full deploy guide:** [`railway/DEPLOY.md`](../railway/DEPLOY.md) — service
topology, IPv6 private networking, per-service env vars, and the shared-secret
wiring. Key points:

- Each repo owns its own ghcr image (tag-triggered).
- Set IPv6 binds for `.railway.internal` reachability: `HOST=::` (playground,
  CP), `HOSTNAME=::` (ui-console), `ACDP_REGISTRY__REGISTRY__BIND=::`
  (registries).
- Give each service a deterministic internal port and wire the shared secrets
  above across services.

## CI/CD

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | push / PR | `ruff check` + `ruff format --check`, the offline unit suite with an 80% coverage gate on Python 3.12 + 3.13, smoke test; PRs also build the playground image (no push); live conformance on manual `workflow_dispatch` **or the weekly schedule** (boots registry-a + control-plane, uploads compose logs on failure) |
| `deploy-images.yml` | `v*` tag / dispatch | Build + push full-stack ghcr images |
| `notify-website.yml` | push to `main` touching `docs/**` or `README.md` | Dispatch a `docs-updated` event to `acdp-website` |
