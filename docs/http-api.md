# HTTP API

The playground exposes a small FastAPI surface. The base URL is
`http://localhost:8000` by default. Interactive docs are available at `/docs`
(Swagger) and `/redoc` when the server is running.

## Route summary

| Method | Path | Status | Purpose |
|--------|------|--------|---------|
| `GET` | `/` | 200 | Service metadata + endpoint list |
| `GET` | `/healthz` | 200 | Liveness |
| `GET` | `/readyz` | 200 | Readiness — pings registry-a and registry-b |
| `GET` | `/scenarios` | 200 | List the scenario catalog |
| `GET` | `/scenarios/{id}` | 200 / 404 | One scenario's metadata |
| `POST` | `/runs` | 202 / 404 | Start a scenario run (404: unknown scenario) |
| `GET` | `/runs/{id}` | 200 / 404 | Poll run status + result |
| `GET` | `/runs/{id}/events` | 200 | SSE stream of run events |
| `GET` | `/contexts/{ctx_id}` | 200 / 404 | Retrieve a context from the right registry |
| `POST` | `/webhooks/acdp` | 204 / 400 / 401 | Registry → playground webhook ingestion (400: bad JSON; 401: missing/invalid signature) |

## Health

### `GET /healthz`

```json
{ "ok": true, "service": "acdp-playground", "version": "0.1.0" }
```

`version` is the installed distribution's version (`"unknown"` if the app is
run from an uninstalled source tree).

### `GET /readyz`

Best-effort pings both registries; one registry being down does not fail the
response.

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
- `registry_mode` *(optional)* — overrides the scenario default

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

Checks both the in-flight queue and persisted results; **404** if the run is
unknown and not in flight.

### `GET /runs/{run_id}/events`  (SSE)

Media type `text/event-stream`. Each message is:

```
data: {"type":"acdp.publish","run_id":"9f1c...","ts":"...","agent_id":"did:web:...","ctx_id":"acdp://...","title":"..."}

```

Behavior:

- **Run in flight** — drains the run's queue as it fills. Sends a keepalive
  comment every 15s on idle. Terminates on `run.complete` or `run.error`.
- **Run already finished** — replays the final result and an end marker.
- The queue is cleaned up on client disconnect.

#### `StepEvent` schema

| Field | Notes |
|-------|-------|
| `type` | One of the event types below |
| `run_id` | Correlates to the run |
| `scenario_id` | Set on `run.started` / `run.complete` / `run.error` |
| `ts` | UTC ISO-8601 timestamp |
| `agent_id` | Emitting agent's DID (when applicable) |
| `framework` | `langchain` / `crewai` / `langgraph` |
| `ctx_id`, `title`, `derived_from` | Context details on publish/retrieve |
| `preview` | Short LLM-output preview |
| `contexts_produced`, `lineage_graph` | On `run.complete` |
| `error` | On `run.error` |
| `registry_authority`, `tenant_id`, `event_id` | Routing / dedup metadata |
| `key_fingerprint`, `receipt_present` | ACDP 0.2 trust signals lifted from webhook payloads |

**Event types:** `agent.started`, `llm.thinking`, `acdp.publish`,
`acdp.retrieve`, `acdp.search`, `acdp.verify`, `auth.token`, `auth.revoke`,
`policy.check`, `scenario.note`, `webhook.received`, `run.started`,
`run.complete`, `run.error`.

## Contexts

### `GET /contexts/{ctx_id}`

`ctx_id` is the full ACDP URI (e.g.
`acdp://registry-a.playground.local/<uuid>`); it is matched as a path
parameter. The playground extracts the authority, routes to the matching
registry, and proxies the retrieval. **404** if no registry is configured for
that authority. Registry errors are forwarded as HTTP exceptions.

## Webhooks

### `POST /webhooks/acdp`

The endpoint registries call when a context is published/retrieved/searched.
Returns **204**. The webhook **payload and signing scheme are the registry's** —
see the registry's
[WEBHOOKS.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/WEBHOOKS.md);
the playground is the receiver.

**Signature** — header `X-ACDP-Signature: sha256=<hex>`, a GitHub-style
HMAC-SHA256 of the raw body keyed by `WEBHOOK_SECRET`. A missing or invalid
signature yields **401**.

**Processing:**

1. Validate the body is JSON (**400** otherwise).
2. Parse a `WebhookEvent` (a schema mismatch logs a warning but does not fail).
3. Lift request headers onto the event when not already present
   ([RFC-ACDP-0008](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0008-security.md)
   §6.4): `X-Tenant-Id` → `tenant_id`, `X-ACDP-Event-Id` → `event_id` (dedup
   key), `X-Run-Id` → `run_id`.
4. If `run_id` maps to an in-flight run, convert via `StepEvent.from_webhook`
   and enqueue onto that run's SSE bus (silent drop otherwise).
5. Fire-and-forget forward to the control plane (re-signed with the CP secret),
   preserving the original body, headers, and tenant id.

> In the default demo stack the registry webhook is **disabled** (its SSRF
> policy refuses the loopback `http://playground:8000` target). Webhook-driven
> events are exercised in the unit suite and in deployments where the registry
> can reach the playground over a permitted target.
