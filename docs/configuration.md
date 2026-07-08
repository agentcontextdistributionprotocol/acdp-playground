# Configuration

The playground reads settings from environment variables (and a `.env` file) via
`pydantic-settings` (`playground/config.py`). `get_settings()` is cached. Copy
[`.env.example`](../.env.example) to `.env` to start.

## Core settings

### Registries

| Variable | Default | Notes |
|----------|---------|-------|
| `REGISTRY_A_URL` | `http://localhost:8100` | Registry-a base URL |
| `REGISTRY_B_URL` | `http://localhost:8200` | Registry-b base URL |
| `REGISTRY_C_URL` | `http://localhost:8300` | Registry-c base URL (the receipts-profile registry) |
| `REGISTRY_A_AUTHORITY` | `registry-a.playground.local` | DID authority for registry-a |
| `REGISTRY_B_AUTHORITY` | `registry-b.playground.local` | DID authority for registry-b |
| `REGISTRY_C_AUTHORITY` | `registry-c.playground.local` | DID authority for registry-c |

`Settings.registry_url_for(authority)` and `authority_url_map()` map any of the
three authorities back to its base URL — this is how cross-registry resolution
routes retrievals.

### Registry receipts (ACDP 0.2, RFC-ACDP-0010)

| Variable | Default | Notes |
|----------|---------|-------|
| `REGISTRY_C_RECEIPT_SEED_B64` | *(demo seed baked in)* | Ed25519 signing seed for registry-c's receipts profile; `Settings.receipts_enabled` is `bool(...)` of it and `registry_c_receipt_public_key_b64()` derives the verify key |

### LLM provider

| Variable | Default | Notes |
|----------|---------|-------|
| `LLM_PROVIDER` | `openai` | `openai` \| `anthropic` \| `mock` |
| `LLM_MODEL` | `gpt-4o-mini` | Passed straight to the provider |
| `OPENAI_API_KEY` | — | Required for `openai` |
| `ANTHROPIC_API_KEY` | — | Required for `anthropic` |

Use `LLM_PROVIDER=mock` for fully offline runs (deterministic echo, no key).

### Webhook signing

| Variable | Default | Notes |
|----------|---------|-------|
| `WEBHOOK_SECRET` | `playground-dev-secret` | **Must match** the value the registries are launched with; used to verify inbound `X-ACDP-Signature` |

### Control plane (optional)

| Variable | Default | Notes |
|----------|---------|-------|
| `CONTROL_PLANE_URL` | *(empty)* | Empty disables all CP forwarding; set it to enable |
| `CONTROL_PLANE_HMAC_SECRET` | *(empty)* | Must match the CP's `WEBHOOK_SECRET`; re-signs forwarded webhooks |
| `CONTROL_PLANE_ADMIN_TOKEN` | *(empty)* | Admin bearer for CP admin endpoints (introspection, revocation feed, pinned-key reload); matches a CP `AUTH_ADMIN_API_KEYS` entry |

`Settings.control_plane_enabled` is simply `bool(control_plane_url)`.

### V2 protocol features

| Variable | Default | Notes |
|----------|---------|-------|
| `DEFAULT_SIGNATURE_ALG` | `ed25519` | `ed25519` \| `ecdsa-p256` — default signer for agents that don't override |
| `TENANCY_ENABLED` | `false` | Attach tenant context in tenancy-aware scenarios; off keeps S1–S8 single-tenant |
| `JWT_SIGNING_ALG` | `HS256` | `HS256` \| `EdDSA` — informational on the playground side (it verifies via JWKS when needed) |

### Logging

| Variable | Default | Notes |
|----------|---------|-------|
| `LOG_FORMAT` | `pretty` | `pretty` (human) \| `json` (structured) |
| `LOG_LEVEL` | `INFO` | Standard Python log level |

## The consumer SSRF guard

There is **no env toggle** — `acdp_client.safe_http` is always enforced on the
`data_refs[].location` fetch path (RFC-ACDP-0008 §4.9): https-only,
private/loopback/IMDS blocked, same-authority redirects only, mixed-DNS-answer
rejection — orchestration only; the policy itself is the SDK's. See
[Client SDK → safe_http](client-sdk.md#safe_httppy--consumer-ssrf-guard-orchestration-only).

Optional: `ACDP_RFC_DIR` (default `../agentcontextdistributionprotocol`) points
the JCS-vectors test at the sibling RFC repo; the test skips if absent.

## Downstream service configuration (not owned here)

`docker-compose.full.yml` also sets a number of `CONTROL_PLANE_*` and
`ACDP_REGISTRY__*` variables that configure the **registry and control plane**,
not the playground. The compose file bakes in secure-but-demo-friendly defaults;
`.env.example` lists the overrides (audience binding, strict tenancy, ingest DoS
caps, outbound-webhook SSRF policy, federation feeds, the CP `default`-tenant
fail-fast rule, the registry loopback-bind rule, …).

These are **documented by the projects that own them** — don't treat the
playground as their reference:

- **Control plane:** [CONFIGURATION.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/CONFIGURATION.md) ·
  [AUTH.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/AUTH.md) ·
  [TENANCY.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/TENANCY.md) ·
  [INGEST.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/INGEST.md) ·
  [POLICY.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/POLICY.md)
- **Registry:** [CONFIGURATION.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/CONFIGURATION.md) ·
  [AUTHENTICATION.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/AUTHENTICATION.md) ·
  [MULTI-TENANCY.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/MULTI-TENANCY.md)

The only playground-relevant facts about them are the **shared secrets** that
must line up across services — see
[Deployment → Secrets that must line up](deployment.md#secrets-that-must-line-up).
