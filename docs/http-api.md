# HTTP API

The playground exposes a small FastAPI surface. The base URL is
`http://localhost:8000` by default. Interactive docs are available at `/docs`
(Swagger) and `/redoc`, and the raw schema at `/openapi.json`, when the server
is running. CORS is wide open (`allow_origins=["*"]`, all methods and headers —
`playground/main.py`), which suits a local demo harness, not a public deployment.

## Route summary

| Method | Path | Status | Purpose |
|--------|------|--------|---------|
| `GET` | `/` | 200 | Service metadata + endpoint list |
| `GET` | `/healthz` | 200 | Liveness |
| `GET` | `/readyz` | 200 | Readiness — pings registry-a and registry-b (always 200; read `ok`) |
| `GET` | `/scenarios` | 200 | List the scenario catalog |
| `GET` | `/scenarios/{id}` | 200 / 404 | One scenario's metadata |
| `POST` | `/runs` | 202 / 404 / 422 | Start a scenario run (404: unknown scenario; 422: body fails validation, e.g. a bad `registry_mode`) |
| `GET` | `/runs/{id}` | 200 / 404 | Poll run status + result |
| `GET` | `/runs/{id}/events` | 200 / 404 | SSE stream of run events (404: no live queue and no persisted result) |
| `GET` | `/contexts/{ctx_id}` | 200 / 404 / 502 / *registry status* | Retrieve a context from the right registry (502: the registry served a body not bound to the requested id; other registry errors pass through with the registry's status) |
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
result is used. **404** if neither exists — see the disconnect caveat below.

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
- **Client disconnect (current behavior)** — the run's queue is dropped
  whenever the stream ends for any reason, including a client disconnecting
  mid-run. The scenario keeps running in the background, but until its result
  is persisted both `GET /runs/{id}` and `GET /runs/{id}/events` answer **404**,
  events emitted in that window are not replayable, and webhooks for the run
  are not fanned into SSE. Tracked as
  [acdp-playground#92](https://github.com/agentcontextdistributionprotocol/acdp-playground/issues/92).
  Keep the stream open until the end marker, or poll `GET /runs/{id}` instead
  of reconnecting.

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
(RFC-ACDP-0013 lifecycle), `auth.token`, `auth.revoke`, `policy.check`,
`scenario.note`, `run.started`, `run.complete`, `run.error`, and
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
to the `ctx_id` that was asked for (RFC-ACDP-0006 §4.1 step 7). The body is
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
