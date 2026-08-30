# Deploying the ACDP full stack to Railway

This deploys the whole demo — **2 registries + control plane + playground +
ui-console** — to [Railway](https://railway.com), pulling images from GitHub
Container Registry (ghcr.io). Each repo publishes its **own** image on a `v*`
tag (this repo builds `acdp-playground`); Railway runs them.

```
                         ┌─────────────────────────────┐
   public ── ui-console ─┤  (Next.js UI, public domain) │
   public ── playground ─┤  (FastAPI API, public domain)│
                         └──────────────┬──────────────┘
                  private .railway.internal (IPv6)
        ┌───────────────┬───────────────┼──────────────┐
   registry-a:8100   registry-b:8200   control-plane:3001
```

Only **ui-console** (and optionally **playground**) need a public domain;
everything else talks over Railway's private network.

---

## 0. Key facts that make this work

- **Dynamic `$PORT`.** Railway injects `PORT`. The playground binds it
  (`Dockerfile` CMD); the control plane reads `process.env.PORT`; ui-console
  reads `PORT`; the registry takes `ACDP_REGISTRY_REGISTRY__PORT`. Set an
  **explicit** `PORT` per service so internal addresses are deterministic.
- **Private networking is IPv6.** A service is only reachable at
  `<service>.railway.internal` if it binds `::`, not `0.0.0.0`. Set `HOST=::`
  (playground, CP), `HOSTNAME=::` (ui-console), and
  `ACDP_REGISTRY_REGISTRY__BIND=::` (registries).
- **Shared secrets must match across services** (see the secrets table) — a
  mismatch silently breaks webhook HMAC verification or admin auth.

---

## 1. Build & push the images

Each repo owns and publishes its own ghcr package on a `v*` tag — there is no
central "build everything" job, and no cross-repo PAT is needed (every build
clones only public siblings via the built-in `GITHUB_TOKEN`):

| Image                              | Built by repo        | Workflow                              |
|------------------------------------|----------------------|---------------------------------------|
| `ghcr.io/<owner>/acdp-playground`  | **acdp-playground**  | `.github/workflows/deploy-images.yml` |
| `ghcr.io/<owner>/acdp-registry`    | **acdp-registry-rs** | `.github/workflows/docker.yml`        |
| `ghcr.io/<owner>/acdp-control-plane` | **acdp-control-plane** | `.github/workflows/release.yml`     |
| `ghcr.io/<owner>/acdp-ui-console`  | **acdp-ui-console**  | (its own release workflow)            |

Publish this repo's image (pick one):

```bash
git tag v0.1.0 && git push origin v0.1.0      # tag-triggered
# or: Actions → "Build & push playground image (ghcr)" → Run workflow (manual)
```

Tag the sibling repos the same way to publish the rest. Then make each package
**public** (or grant Railway access): GitHub → the org's *Packages* → each
package → *Package settings* → visibility / add Railway's deploy token. Public
is simplest for a demo.

---

## 2. Create the services

In a new Railway **project**, add five services, each *from a Docker image*
(`+ New → Deploy from Docker image`). Name them exactly as below — the names
become the internal DNS:

| Service         | Image                                  | Public? | Listens on |
|-----------------|----------------------------------------|---------|------------|
| `registry-a`    | `ghcr.io/<owner>/acdp-registry`        | no      | 8100       |
| `registry-b`    | `ghcr.io/<owner>/acdp-registry`        | no      | 8200       |
| `control-plane` | `ghcr.io/<owner>/acdp-control-plane`   | no      | 3001       |
| `playground`    | `ghcr.io/<owner>/acdp-playground`      | yes     | 8000       |
| `ui-console`    | `ghcr.io/<owner>/acdp-ui-console`      | yes     | 3000       |

For the two public services, *Settings → Networking → Generate Domain*, and set
the target port (8000 / 3000). Set the healthcheck path under *Settings →
Deploy* (`/healthz` for registry/CP/playground, `/` for ui-console).

---

## 3. Environment variables

Generate the shared secrets **once** and reuse them consistently:

```bash
openssl rand -base64 32   # → JWT_SECRET (CP) and ACDP_REGISTRY_AUTH__JWT_SECRET
# pick stable strings for the rest
```

### Shared-secret consistency (the easy-to-miss part)

| Secret                     | Must be equal across …                                                        |
|----------------------------|-------------------------------------------------------------------------------|
| registry webhook secret    | `registry-*` `ACDP_REGISTRY_WEBHOOK__SECRET` = `playground` `WEBHOOK_SECRET`  |
| CP ingest HMAC             | `control-plane` `WEBHOOK_SECRET` = `playground` `CONTROL_PLANE_HMAC_SECRET`    |
| CP admin key               | `playground` `CONTROL_PLANE_ADMIN_TOKEN` ∈ `control-plane` `AUTH_ADMIN_API_KEYS` |

### `registry-a`  (registry-b: swap `a`→`b`, port 8100→8200)

The registry runs on built-in defaults overlaid by `ACDP_REGISTRY_*` env (no
config file needed — the image's entrypoint passes none).

```
ACDP_REGISTRY_REGISTRY__AUTHORITY=registry-a.playground.local
ACDP_REGISTRY_REGISTRY__PORT=8100
ACDP_REGISTRY_REGISTRY__BIND=::
ACDP_REGISTRY_REGISTRY__ALLOW_PUBLIC_BIND=true
ACDP_REGISTRY_PLAYGROUND__ENABLED=true
ACDP_REGISTRY_STORAGE__BACKEND=sqlite
ACDP_REGISTRY_STORAGE__SQLITE_PATH=/app/data/registry-a.db
ACDP_REGISTRY_AUTH__ENABLED=true
ACDP_REGISTRY_AUTH__ANONYMOUS_PUBLIC_READS=true
ACDP_REGISTRY_AUTH__REQUIRE_TENANT=false
ACDP_REGISTRY_AUTH__JWT_SECRET=<base64 ≥32 bytes>
ACDP_REGISTRY_WEBHOOK__SECRET=<registry-webhook-secret>
```

> SQLite under `/app/data` is **ephemeral** on Railway (resets on redeploy) —
> fine for a demo. For persistence, attach a Railway **volume** mounted at
> `/app/data`. The full `[section]→ACDP_REGISTRY_SECTION__KEY` mapping mirrors
> `config/registry-a.toml`; add more keys the same way if you need them.

### `control-plane`  (mirrors `docker-compose.full.yml`)

```
PORT=3001
HOST=::
NODE_ENV=production
AUTH_PERSISTENCE=memory
STREAM_HUB_STRATEGY=memory
TOKEN_ISSUANCE_ENABLED=true
JWT_AUTHORITY=control-plane.playground.local
JWT_SIGNING_ALG=HS256
JWT_SECRET=<base64 ≥32 bytes>
JWT_AUDIENCE=control-plane.playground.local
JWT_TTL_SECONDS=3600
CHALLENGE_TTL_SECONDS=300
WEBHOOK_SECRET=<cp-ingest-hmac>
AUTH_API_KEYS=<cp-api-key>
AUTH_ADMIN_API_KEYS=<cp-admin-key>
POLICY_BACKEND=static
DOMAIN_PACKS=finance
AUTH_REQUIRE_TENANT=false
INGEST_MAX_BODY_BYTES=1048576
INGEST_MAX_JSON_DEPTH=32
INGEST_STRICT_TENANT=false
```

### `playground`

```
PORT=8000
HOST=::
LLM_PROVIDER=mock          # or `openai` / `anthropic` + the matching API key
REGISTRY_A_URL=http://registry-a.railway.internal:8100
REGISTRY_B_URL=http://registry-b.railway.internal:8200
REGISTRY_A_AUTHORITY=registry-a.playground.local
REGISTRY_B_AUTHORITY=registry-b.playground.local
CONTROL_PLANE_URL=http://control-plane.railway.internal:3001
CONTROL_PLANE_HMAC_SECRET=<cp-ingest-hmac>      # == control-plane WEBHOOK_SECRET
CONTROL_PLANE_ADMIN_TOKEN=<cp-admin-key>        # ∈ control-plane AUTH_ADMIN_API_KEYS
WEBHOOK_SECRET=<registry-webhook-secret>        # == registry ACDP_REGISTRY_WEBHOOK__SECRET
```

### `ui-console`

```
PORT=3000
HOSTNAME=::
PLAYGROUND_BASE_URL=http://playground.railway.internal:8000
CONTROL_PLANE_BASE_URL=http://control-plane.railway.internal:3001
REGISTRY_A_BASE_URL=http://registry-a.railway.internal:8100
REGISTRY_B_BASE_URL=http://registry-b.railway.internal:8200
CONTROL_PLANE_API_KEY=<cp-admin-key>
```

---

## 4. Deploy order & verification

Deploy `registry-a`, `registry-b`, `control-plane` first (no dependencies),
then `playground`, then `ui-console`. After each is green:

```bash
# public playground domain
curl https://<playground-domain>/healthz        # → 200
curl https://<playground-domain>/scenarios | jq 'length'   # → 33

# run an offline scenario end-to-end (no backends needed)
curl -X POST https://<playground-domain>/runs \
  -H 'content-type: application/json' \
  -d '{"scenario_id":"s21_capabilities_p256","inputs":{}}'

# a registry-backed scenario (exercises the private network)
curl -X POST https://<playground-domain>/runs \
  -H 'content-type: application/json' \
  -d '{"scenario_id":"s1_single_publish","inputs":{}}'
```

Open the **ui-console** public domain to drive the stack from the browser.

---

## 5. Troubleshooting

- **A service can't reach another (`Connection refused` on `*.railway.internal`).**
  The target isn't bound to IPv6. Confirm `HOST=::` / `HOSTNAME=::` /
  `ACDP_REGISTRY_REGISTRY__BIND=::`, and that the port in the URL matches the
  target's listen port.
- **Registry rejects its bind (`refuses non-loopback bind`).** Set
  `ACDP_REGISTRY_REGISTRY__ALLOW_PUBLIC_BIND=true` (and/or
  `ACDP_REGISTRY_PLAYGROUND__ENABLED=true`).
- **Forwarded webhooks 401 at the CP, or registry webhooks fail HMAC.** A
  secret mismatch — re-check the shared-secret table in §3.
- **`data_ref` SSRF scenarios (e.g. S16) or CP outbound webhooks fail against
  internal hosts.** The consumer `data_ref` fetch and CP outbound-webhook paths
  enforce an SSRF policy that blocks private addresses by design;
  `*.railway.internal` is private. This is expected — those specific scenarios
  need a public data host. Registry/CP API calls the playground makes are *not*
  SSRF-screened (they use the configured base URLs).
- **ghcr pull denied.** Make the packages public, or add Railway's registry
  credentials to each service.
- **First request after a deploy is slow.** Cold start only; the image is
  prebuilt (no runtime compile — `uv run --no-sync`).
