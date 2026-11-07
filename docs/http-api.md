# HTTP API

The playground exposes a small FastAPI surface. The base URL is
`http://localhost:8000` by default. Interactive docs are available at `/docs`
(Swagger) and `/redoc`, and the raw schema at `/openapi.json`, when the server
is running. CORS is wide open (`allow_origins=["*"]`, all methods and headers —
`playground/main.py`); access control is the API key below, not CORS.

## Authentication: `x-api-key`

Every route except `GET /healthz` and `POST /webhooks/acdp` sits behind a shared
key sent as the **`x-api-key`** header (`playground/security.py`). That covers
`/`, `/readyz`, `/docs`, `/redoc`, `/openapi.json`, `/scenarios*`, `/runs*`
including the SSE stream, `/contexts/*`, `/registries/*`, and any unknown path.
`/webhooks/acdp` authenticates each delivery with its own HMAC signature.

| `PLAYGROUND_REQUIRE_API_KEY` | Missing or wrong key | Valid key |
|------------------------------|----------------------|-----------|
| `false` (default) | request proceeds (a wrong key is logged and treated as absent) | request proceeds, trusted |
| `true` | **401** `{"detail": "missing or invalid x-api-key"}` | request proceeds, trusted |

With `PLAYGROUND_REQUIRE_API_KEY=true` and no `PLAYGROUND_API_KEY`, the service
refuses to start; so does `true` with an empty `WEBHOOK_SECRET`, since
`/webhooks/acdp` skips the key only because its signature authenticates it.
Browser CORS preflights are answered before the gate.

**Client IP.** A trusted (valid-key) caller that fronts end users, such as the UI
console, forwards the user's address in **`X-ACDP-Client-IP`**: a single IPv4
or IPv6 address, not an `X-Forwarded-For`-style list. The header is honoured
only alongside a valid key; otherwise the client IP is the socket peer, so a
caller can't choose its own rate-limit bucket. Limits are kept per IPv4 address
and per IPv6 /64 (an IPv4-mapped IPv6 address counts as its IPv4). A keyed request with the header
missing or unparsable is charged to the socket peer too, which behind the
console means every user shares one bucket, so send the key and the header
together.

## Limits

| Limit | Default | Env var | Scope | When exceeded |
|-------|---------|---------|-------|---------------|
| Run launches per client IP | 5 per 600 s | `RUN_RATE_LIMIT_PER_IP`, `RUN_RATE_LIMIT_WINDOW_SECONDS` | `POST /runs`, sliding window, in memory | **429** `run_rate_limited` + `Retry-After` |
| Concurrent runs | 3 | `MAX_CONCURRENT_RUNS` | whole service, in memory | **429** `max_concurrent_runs` + `Retry-After: 10` |
| Run duration | 600 s | `RUN_TIMEOUT_SECONDS` | each run | run ends with `run.error` (`RUN_TIMEOUT_SECONDS`) and frees its slot |
| LLM calls per client IP per UTC day / month | 30 / 300 | `LLM_QUOTA_PER_IP_PER_DAY`, `LLM_QUOTA_PER_IP_PER_MONTH` | each real LLM call, Postgres | run continues on the mock LLM, marked `llm_quota_exceeded` |
| LLM calls, global, per UTC day / month | 1,000 / 10,000 | `LLM_QUOTA_GLOBAL_PER_DAY`, `LLM_QUOTA_GLOBAL_PER_MONTH` | each real LLM call, Postgres | same |

Per-IP limits (both rows) apply to requests with a valid key. They apply to
keyless requests only once `PLAYGROUND_REQUIRE_API_KEY=true`, when such requests
get 401 anyway. During the rollout, before callers send the key, a keyless
request's socket peer is the platform's edge proxy, shared by every user, so a
per-IP bucket would throttle everyone together. The global quotas and the
concurrency cap apply to every request from the start.

A 429 body is `{"detail": {"code", "limit", "retry_after", "detail"}}`. An LLM
quota hit never fails the run or falls back silently. The run emits one
`llm.quota_exceeded` event (`quota`, `limit`, `resets_at`), and both the
`run.complete` event and `RunResult.summary` carry:

```json
{
  "llm_quota_exceeded": true,
  "llm_quota": {"quota": "per_ip_daily", "limit": 30, "resets_at": "2026-11-08T00:00:00Z"},
  "llm_calls_on_mock": 2
}
```

`quota` is `per_ip_daily`, `per_ip_monthly`, `global_daily`, `global_monthly`, or
`quota_store_unavailable` (the counter store errored or didn't answer within 10 s, so the call was refused
rather than spent uncounted; `limit`/`resets_at` are then null). Counters live in
Postgres (`DATABASE_URL`, table `playground_llm_usage`) so they survive
redeploys; without `DATABASE_URL` they are in memory and reset on restart.

## Route summary

| Method | Path | Status | Purpose |
|--------|------|--------|---------|
| `GET` | `/` | 200 | Service metadata + endpoint list |
| `GET` | `/healthz` | 200 | Liveness |
| `GET` | `/readyz` | 200 | Readiness — pings registry-a and registry-b (always 200; read `ok`) |
| `GET` | `/scenarios` | 200 | List the scenario catalog |
| `GET` | `/scenarios/{id}` | 200 / 404 | One scenario's metadata |
| `POST` | `/runs` | 202 / 404 / 422 / 429 | Start a scenario run (404: unknown scenario; 422: body fails validation, e.g. a bad `registry_mode`; 429: a [launch limit](#limits)) |
| `GET` | `/runs/{id}` | 200 / 404 | Poll run status + result |
| `GET` | `/runs/{id}/events` | 200 / 404 | SSE stream of run events (404: no live queue and no persisted result) |
| `GET` | `/contexts/{ctx_id}` | 200 / 404 / 502 / *registry status* | Retrieve a context from the right registry (502: the registry served a body not bound to the requested id; other registry errors pass through with the registry's status) |
| `GET` | `/registries/{a\|b}/{path}` | *registry status* / 404 / 422 / 502 | Allow-listed read-only [registry passthrough](#registry-passthrough) |
| `POST` | `/webhooks/acdp` | 204 / 400 / 401 | Registry → playground webhook ingestion (400: bad JSON; 401: missing/invalid signature when `WEBHOOK_SECRET` is set) |

## Health

### `GET /healthz`

```json
{ "ok": true, "service": "acdp-playground", "version": "0.1.0" }
```

`version` is the installed distribution's version (`"unknown"` if the app is
run from an uninstalled source tree).

### `GET /readyz`

Best-effort pings both registries. The status is **always 200**; `ok` is
`registry_a and registry_b`, so one registry being down shows up as
`"ok": false` in the body, not as an error status.

```json
{ "ok": true, "registry_a": true, "registry_b": true }
```

## Scenarios

### `GET /scenarios`

```json
{
  "scenarios": [
    {
      "id": "s4_chain",
      "name": "Linear Chain A→B→C",
      "description": "...",
      "registry_mode": "single",
      "agent_count": 3,
      "framework": "langchain",
      "default_inputs": { "topic": "GPU supply chains" }
    }
  ]
}
```

`registry_mode` is one of `single` | `dual` | `cross_org`; `framework` is one of
`langchain` | `crewai` | `langgraph` | `mixed` (catalog metadata — every
scenario currently declares `langchain`).

### `GET /scenarios/{scenario_id}`

Returns the single serialized `ScenarioDef`, or **404** if unknown.

## Runs

### `POST /runs`

**Request body** (`RunRequest`):

```json
{
  "scenario_id": "s4_chain",
  "inputs": { "topic": "GPU supply chains" },
  "registry_mode": "single"
}
```

- `scenario_id` *(required)* — must exist (404 otherwise)
- `inputs` *(optional)* — merged over the scenario's `default_inputs`
- `registry_mode` *(optional)* — `single` | `dual` | `cross_org`; overrides the
  scenario default. Any other value (or a malformed body) is a **422** from
  FastAPI's request validation.

**Response** (**202 Accepted**):

```json
{
  "run_id": "9f1c...",
  "scenario_id": "s4_chain",
  "status": "running",
  "stream_url": "/runs/9f1c.../events",
  "started_at": "2026-06-10T12:00:00Z"
}
```

The run executes as a background task. Subscribe to `stream_url` for live events.

### `GET /runs/{run_id}`

```json
{
  "run_id": "9f1c...",
  "status": "running",      // running | complete | failed
  "result": null             // RunResult once complete
}
```

`result`, once present, is the `RunResult`: `run_id`, `scenario_id`, `status`
(`complete` | `failed`), `contexts` (ctx ids produced), `lineage_graph`,
`summary` (scenario-specific, e.g. `degraded: true`), and `error` (with
traceback, when the scenario raised).

A run counts as in flight while its SSE queue exists; otherwise the persisted
result is used. **404** if neither exists.

### `GET /runs/{run_id}/events`  (SSE)

Media type `text/event-stream`. Each message is:

```
data: {"type":"acdp.publish","run_id":"9f1c...","ts":"...","agent_id":"did:key:z6Mk...","ctx_id":"acdp://...","title":"..."}

```

Behavior:

- **Run in flight** — drains the run's queue as it fills. Sends a keepalive
  comment (`: keepalive`) every 15s on idle. After the first `run.complete` or
  `run.error` it sends a final `event: end` / `data: complete` marker and
  closes.
- **Run already finished** — sends one `data:` message carrying the serialized
  `RunResult` (not a `StepEvent`), then the same `event: end` marker.
- **No queue and no result** — **404**.
- **Client disconnect** — the run's queue survives a client dropping the
  stream mid-run. The scenario keeps running and `GET /runs/{id}` keeps
  answering. Reconnecting to `GET /runs/{id}/events` resumes from the events
  not yet dequeued (an event in flight at the moment of disconnect can be
  lost; if that was the terminal event, the reconnect gets the persisted
  result replay instead). The queue is dropped once the terminal event has
  been streamed. Use one subscriber per run: concurrent subscribers split the
  events between them. A run whose stream is never opened, or is abandoned
  mid-run, keeps its queue (which grows with the run's events) until the
  process restarts.

#### `StepEvent` schema

| Field | Notes |
|-------|-------|
| `type` | One of the event types below |
| `run_id` | Correlates to the run |
| `scenario_id` | Set on `run.started` / `run.complete` / `run.error` |
| `ts` | UTC ISO-8601 timestamp |
| `agent_id` | Emitting agent's DID (when applicable) |
| `framework` | Emitting agent's adapter: `langchain` / `crewai` / `langgraph`, or `base` for a bare `BasePlaygroundAgent` (also stamped into published metadata as `agent_framework`) |
| `ctx_id`, `title`, `derived_from` | Context details on publish/retrieve |
| `preview` | Short LLM-output preview |
| `contexts_produced`, `lineage_graph` | On `run.complete` |
| `error` | On `run.error` |
| `status` | The scenario's `RunResult.status` (`"complete"`/`"failed"`), on both `run.complete` and `run.error` — a scenario can return without raising but with `status="failed"` (an internal assertion failing), which still streams `run.complete`; check this field (or `GET /runs/{id}`) rather than the event `type` alone to tell that apart from a real success |
| `registry_authority`, `tenant_id`, `event_id` | Routing / dedup metadata |
| `key_fingerprint`, `receipt_present` | ACDP 0.2 trust signals lifted from webhook payloads |

**Event types:** `agent.started`, `llm.thinking`, `acdp.publish`,
`acdp.retrieve`, `acdp.search`, `acdp.verify`, `acdp.retract`, `acdp.republish`
([RFC-ACDP-0013](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0013-lifecycle-events.md) lifecycle), `auth.token`, `auth.revoke`, `policy.check`,
`scenario.note`, `llm.quota_exceeded` (see [Limits](#limits)), `run.started`,
`run.complete`, `run.error`, and
`webhook.received` — the fallback for a registry webhook whose type validates
but has no `acdp.*` mapping (`context_published`/`_retrieved`/`_retracted`/
`_republished` and `search_executed` map to the `acdp.*` types).

## Contexts

### `GET /contexts/{ctx_id}`

`ctx_id` is the full ACDP URI (e.g.
`acdp://registry-a.playground.local/<uuid>`); it is matched as a path
parameter. The playground extracts the authority, routes to the matching
registry, and proxies the retrieval. **404** if no registry is configured for
that authority. A registry HTTP error is passed through with the **registry's
status code** and its body as the `detail`.

**502** if the retrieval succeeds but the body the registry served is not bound
to the `ctx_id` that was asked for ([RFC-ACDP-0006](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0006-cross-registry.md) §4.1 step 7). The body is
never relayed in that case — passing it on would launder the substitution
through this host — and the detail names which way it failed:

```json
{
  "detail": {
    "code": "context_binding_failed",
    "reason": "mismatch",
    "requested_ctx_id": "acdp://registry-a.playground.local/642fac39-91a6-479e-8fec-bf3d933ba7cf",
    "served_ctx_id": "acdp://registry-a.playground.local/a0dc1071-0be3-4238-972d-9cb69e054c06",
    "detail": "..."
  }
}
```

`reason` is `mismatch` (both ids parse and differ — context substitution),
`malformed` (either id fails the SDK's `CtxId::parse`, or the served body does
not deserialize), or `unverifiable` (a body was served carrying no `ctx_id`, so
the check cannot run). It is a **502**, not a 4xx: the fault is the upstream
registry's.

## Registry passthrough

### `GET /registries/{registry}/{path}`

Read-only passthrough to registry-a (`a`) or registry-b (`b`), using the
configured `REGISTRY_A_URL` / `REGISTRY_B_URL` (the private network in
production), so callers never need the registries' public domains. Only these
paths are forwarded; anything else is **404** before any upstream request:

| Path | Registry route |
|------|----------------|
| `/registries/{a\|b}/healthz` | `GET /healthz` |
| `/registries/{a\|b}/contexts/search?...` | `GET /contexts/search` (query string forwarded as-is) |
| `/registries/{a\|b}/lineages/{lineage_id}` | `GET /lineages/{lineage_id}` |
| `/registries/{a\|b}/lineages/{lineage_id}/current` | `GET /lineages/{lineage_id}/current` |
| `/registries/{a\|b}/.well-known/acdp.json` | capabilities |
| `/registries/{a\|b}/.well-known/jwks.json` | JWKS |
| `/registries/{a\|b}/.well-known/did.json` | the registry's own DID document |

The registry's status and body pass through, with `content-type`,
`cache-control`, `etag`, `last-modified`, `retry-after` and `vary`. Only `Accept`
and `If-None-Match` are forwarded upstream; the caller's `x-api-key` never is.
Redirects are not followed. Other registry names are **422**, other methods
**405**, and an unreachable registry is **502** `registry_unreachable`. The list
mirrors the UI console's registry allowlist.

## Webhooks

### `POST /webhooks/acdp`

The endpoint registries call when a context is published/retrieved/searched/
retracted/republished. The webhook **payload and signing scheme are the
registry's** — see the registry's
[WEBHOOKS.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/WEBHOOKS.md);
the playground is the receiver. Receiver-side behavior:

1. **Signature** — when `WEBHOOK_SECRET` is **empty, verification is skipped**.
   Otherwise `X-ACDP-Signature` must be present, use the `sha256=` prefix, and
   match; anything else is **401**.
2. **JSON** — a body that is not JSON is **400**.
3. **Schema** — a body that does not parse as a `WebhookEvent` is logged and
   answered **204**, but is *not* enqueued and *not* forwarded.
4. **Header lift** — `X-Tenant-Id` → `tenant_id`, `X-ACDP-Event-Id` →
   `event_id` (dedup key), `X-Run-Id` → `run_id`, each only when the body did
   not already carry it
   ([RFC-ACDP-0008](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0008-security.md)
   §6.4).
5. **SSE fan-in** — if `run_id` names a run with a live queue, the event is
   converted via `StepEvent.from_webhook` and enqueued; otherwise it is dropped
   silently.
6. **Control-plane forward** — scheduled as a background task (it sends nothing when
   `CONTROL_PLANE_URL` is empty, though the reserved-tenant check below still runs first) that POSTs the original body to the CP's
   `/ingest/acdp`. It carries `X-ACDP-Event`, `X-ACDP-Event-Id`, `X-Run-Id`
   (each when the inbound request had it) and `X-Tenant-Id` (the lifted
   tenant), plus `X-ACDP-Signature` re-computed with
   `CONTROL_PLANE_HMAC_SECRET` — only when that secret is set; otherwise the
   forward is unsigned. If the tenant is the reserved `default` sentinel,
   `reject_reserved_tenant` raises inside that background task: nothing is
   forwarded, the registry has already received its 204, and the error only
   appears in the log as an unhandled task exception.

Steps 4 and 5 run outside the schema guard, so an unexpected failure there
returns a **5xx** to the registry, which then retries the delivery (the
step-6 forward runs detached and cannot change the response).

> In the default demo stack the registry webhook is **disabled** (its SSRF
> policy refuses the loopback `http://playground:8000` target). Webhook-driven
> events are exercised in the unit suite and in deployments where the registry
> can reach the playground over a permitted target.
