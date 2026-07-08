# Client library (`acdp_client`)

`acdp_client` is the **playground's own** async `httpx` + Pydantic layer that
drives the `acdp` SDK over HTTP. It owns **transport and host-language
orchestration**; it does **not** reimplement any protocol primitive.

> **Boundary.** All cryptography (signing/verification), JCS canonicalization,
> SSRF IP/scheme classification, and `did:web` resolution are **delegated to
> the `acdp` SDK**
> (`acdp-rs`, imported via its `acdp-py` bindings). The playground's client never
> goes through the SDK's Rust `RegistryClient`, so it keeps only the parts a host
> application must own: the `httpx` calls, DNS resolution, the mixed-answer loop,
> redirect handling, and Python-friendly typed exceptions. For the primitives
> themselves see the SDK docs:
> [producing](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/producing.md),
> [consuming](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/consuming.md),
> [errors](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/errors.md),
> [security](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md).

## Modules

| Module | Responsibility |
|--------|----------------|
| `client.py` | `AcdpClient` — async client for one registry; typed HTTP errors |
| `models.py` | Pydantic wire types + error-envelope parsing + error-code tables |
| `token_manager.py` | Drives the registry's challenge → sign → token flow; caches + refresh telemetry |
| `signing.py` | Thin `Producer` abstraction + verify helpers over the SDK |
| `identifiers.py` | Authority + reserved-tenant validation (mirrors the server rule client-side) |
| `safe_http.py` | Host-language orchestration for the consumer SSRF guard |
| `retry_after.py` | RFC 9110 `Retry-After` parsing |

## `AcdpClient`

An async client bound to **one** registry. Construct with a base URL; optionally
attach a `Producer` + `TokenManager` for transparent bearer-token injection,
proactive refresh, and a single 401 retry.

```python
client = AcdpClient(
    base_url,
    *,
    bearer_token=None,
    run_id=None,
    timeout=30.0,
    http=None,               # inject an httpx.AsyncClient (tests use MockTransport)
    producer=None,
    token_manager=None,
    tenant_id=None,
    tenant_header_mode="fallback",
)
```

The client is an async context manager; call `aclose()` (or use
`async with`) when constructing it directly — scenarios normally get clients
from `AgentBundle`, which closes them at run end.

### Methods

These wrap the registry's HTTP surface — see the registry's
[HTTP-API.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/HTTP-API.md)
for the endpoint contracts they call.

| Method | Maps to | Notes |
|--------|---------|-------|
| `publish(request_json, idempotency_key=None)` | `POST /contexts` | Forwards `Idempotency-Key` verbatim → `PublishResponse` |
| `retrieve(ctx_id)` | `GET /contexts/{id}` | → `FullContext` |
| `retrieve_raw(ctx_id)` | `GET /contexts/{id}` | Unparsed dict (preserves registry-assigned fields) |
| `retrieve_body(ctx_id)` | `GET /contexts/{id}/body` | → `Body` |
| `search(...)` | `GET /contexts/search` | Filters: `q`, `context_type`, `domain`, `agent_id`, `tags`, `derived_from`, `visibility`, `limit`, `cursor` → `SearchResponse`; raises `CursorError` |
| `search_all(...)` | paginated search | Async-yields every `SearchHit`; continues through empty-but-cursored pages |
| `lineage(lineage_id)` | `GET /lineages/{id}` | → `list[FullContext]` |
| `current(lineage_id)` | `GET /lineages/{id}/current` | → newest non-superseded, non-retracted `FullContext`; surfaces `lineage_head_receipt` (RFC-ACDP-0011) verbatim |
| `retract(ctx_id, event_json)` | `POST /contexts/{id}/retract` | Wraps the signed lifecycle event in the closed `{"event": …}` envelope, byte-verbatim → post-transition `FullContext` (RFC-ACDP-0013) |
| `republish(ctx_id, event_json)` | `POST /contexts/{id}/republish` | Reverses a retraction; same envelope → `FullContext` |
| `log_checkpoint()` | `GET /log/checkpoint` | Signed tree head, verbatim dict for `AcdpVerifier.verify_log_checkpoint` (RFC-ACDP-0012) |
| `log_proof(ctx_id=…/leaf_index=…[, tree_size=…] \| first=…, second=…)` | `GET /log/proof` | Inclusion or consistency proof (mutually-exclusive modes), verbatim dict |
| `log_entries(start, end)` | `GET /log/entries` | Leaf page (0-based, end-exclusive; server caps 256/page), verbatim dict |
| `resolve(ctx_id, authority_map)` | cross-registry | Routes retrieval to the right registry by authority |
| `healthz()` | `GET /healthz` | → bool |
| `fetch_data_ref(data_ref, policy)` | SSRF-guarded fetch | Delegates to `safe_http`; verifies `content_hash` |

The lifecycle and `/log` responses that carry registry signatures are kept as
**verbatim dicts** (like `retrieve_raw`) rather than re-modelled: the SDK's
verifiers hash the wire JSON *as received*, so the client never re-serializes
what the registry signed. Signing a lifecycle event stays with the producer —
see `playground/scenarios/_receipts.py::mint_lifecycle_event` for the
RFC-ACDP-0013 §5 construction over SDK primitives.

### What the client adds on top of the registry

- **Bearer precedence:** static `bearer_token` > `token_manager` > none.
- **Retry:** only **401** triggers a refresh-and-retry (stale token). A **403**
  is terminal.
- **Tenant header:** `tenant_header_mode="fallback"` suppresses `X-Tenant-Id`
  when an authenticated JWT carries the authoritative `tenant` claim, so the
  header can never contradict the claim. It is only a fallback for unbound
  producer-signed publishes. The full tenancy rules are the registry's —
  see [MULTI-TENANCY.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/MULTI-TENANCY.md).
- **Cursor pagination** that walks the whole sequence, continuing through an
  empty-but-cursored page (discovery semantics defined in
  [RFC-ACDP-0005](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0005-discovery.md)).

### Typed errors

The playground parses the registry's error envelope into Python exceptions for
ergonomic handling. **The envelope format and the error codes are defined by the
protocol/SDK, not here** — see
[`acdp-rs` errors.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/errors.md).
All except `CursorError` subclass `AcdpHTTPError`, which exposes `.status`,
`.body`, `.url`, plus the parsed `.code`, `.details`, and `.reason`
(`CursorError` is a plain `RuntimeError` carrying `.code` and `.message`):

| Exception | Trigger |
|-----------|---------|
| `AcdpHTTPError` | Any non-2xx registry response |
| `SupersededError` | Rejected supersession; `.reason` carries the registry subtype |
| `NotAuthorizedError` | **403** — authenticated but not permitted (terminal) |
| `PayloadTooLargeError` | **413** — oversized body, even from outer middleware |
| `CursorError` | **400** with a cursor error code |
| `ImmutableFieldError` | **400** `immutable_field` — a lifecycle request touched immutable body content (RFC-ACDP-0013) |
| `InvalidLifecycleTransitionError` | **409** `invalid_lifecycle_transition` — retract of an already-retracted / republish of a never-retracted context |
| `InvalidLogProofError` | **502** `invalid_log_proof` — a transparency-log artifact failed verification on a federation/consumer path (RFC-ACDP-0012) |

`models.py` also defines the code tables (`ERROR_CODES`,
`SIGNATURE_ERROR_CODES`, `LIFECYCLE_ERROR_CODES`) and
`parse_error_envelope(payload)` so scenarios can
branch on a machine code. These mirror the registry's emitted codes; they are
**not** an independent source of truth.

## `TokenManager`

Drives the registry's **challenge → sign → token** flow and caches the result
per `(agent, registry)` with single-flight refresh. The flow itself (challenge
issuance, signature verification, JWT minting) is the registry's / control
plane's — see
[registry AUTHENTICATION.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/AUTHENTICATION.md)
and [control-plane AUTH.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/AUTH.md).

```python
tm = TokenManager(http=None, leeway_seconds=30, timeout=15.0)  # all kwargs-only
cached = await tm.token_for(producer, registry_base_url)   # CachedToken
tm.invalidate(producer, registry_base_url)                  # force refresh
await tm.revoke(producer, registry_base_url)                # RFC 7009
```

`default_token_manager()` returns a process-wide shared instance for callers
that don't manage their own lifecycle.

What the playground adds:

- **Proactive refresh** before expiry (configurable leeway) and one **reactive
  401** retry.
- **Cooperative throttling** — honors a `429/503` + `Retry-After` with one
  capped retry.
- **Refresh-reason telemetry** — every mint logs `refresh_reason` (the
  exported `RefreshReason` values: `first_use` / `proactive_refresh` /
  `reactive_401`), `algorithm`, `ttl_seconds`, `elapsed_ms`.
  `CachedToken.aud` peeks the JWT `aud` claim for
  diagnostics only — verification belongs to the issuer.

**Exceptions:** `TokenError` (base), `ChallengeError`, `TokenIssueError`.
(`TokenAuthError` is exported for callers but is not currently raised by the
manager itself — a 401 that survives the refresh-and-retry surfaces as the
request's own `AcdpHTTPError`/`NotAuthorizedError`.)

## `signing.py` — `Producer` abstraction

A thin duck-typed union over the SDK's signers so scenarios don't branch on
algorithm. `Producer` is `acdp.AcdpProducer` (Ed25519) **or**
`acdp.AcdpP256Producer` (P-256); both expose `agent_did`, `key_id`,
`sign_challenge()`, `build_publish_request()`, `build_supersede_request()`.

| Helper | Returns |
|--------|---------|
| `producer_algorithm(producer)` | `"ed25519"` or `"ecdsa-p256"` (the exported `ALG_ED25519` / `ALG_P256` constants) |
| `is_p256(producer)` | bool |
| `public_key_material(producer)` | The public key in the algorithm's encoding |
| `verify_signature(...)` | Delegates to the SDK verifier |

**The actual signing/verification math lives in the SDK** — see
[`acdp-rs` producing.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/producing.md)
and [security.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md).
These helpers only pick the right SDK call and normalize the wire encoding.

## `identifiers.py`

Mirrors server-side validation client-side so a caller fails fast:

- `is_valid_authority(host)` / `validate_origin_registry(value)` — enforce a bare
  DNS hostname (the context-body rules in
  [RFC-ACDP-0002](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0002-context-body.md)).
- `RESERVED_TENANT = "default"` + `is_reserved_tenant(t)` /
  `reject_reserved_tenant(t)` — the reserved
  tenant can never be *asserted* (the registry returns 400, the CP 403); this
  mirrors that rule. See scenario **S20** and the registry's
  [MULTI-TENANCY.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/MULTI-TENANCY.md).

## `safe_http.py` — consumer SSRF guard (orchestration only)

Screens any `data_refs[].location` fetch before the consumer pulls it. **The
per-address/URL classification — which IP ranges and schemes are forbidden — is
the SDK's `AcdpSsrfPolicy`**, defined by
[RFC-ACDP-0008 (security)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0008-security.md)
and documented in
[`acdp-rs` security.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md).
This module owns only the host-language pieces that the SDK can't:

- DNS resolution and the **mixed-answer loop** (reject the whole answer set if
  any resolved IP is forbidden)
- The `httpx` fetch, **same-authority redirect** enforcement, and size/timeout
  caps
- `content_hash` verification after fetch (`DataRefHashMismatch` on mismatch)

`SsrfPolicy` (the Python wrapper) carries the knobs — `allow_loopback`,
`max_redirects`, `max_bytes`, `connect_timeout`, `total_timeout` — and exposes
`production()` / `allow_test_loopback()`. `SsrfError.reason` surfaces the SDK's
stable rejection token (`loopback`, `private`, `imds`, `non_https`,
`cross_authority`, …) plus host-language reasons (`dns_failure`,
`cross_authority_redirect`, `response_too_large`, …).

A `Resolver` callable can be injected for tests — this is how **S16** runs fully
offline.

## did:web re-exports

For consumer-side DID resolution the package re-exports the SDK's `AcdpDid`,
`AcdpDidDocument`, and `DidResolutionError` — the resolution logic (including
the assertionMethod-authorization and algorithm-downgrade defenses of
RFC-ACDP-0008 §3.9) is entirely the SDK's; `acdp_client` only surfaces the
names so scenarios import one package.

## Wire types (`models.py`)

Pydantic types over the registry's JSON, all `extra="allow"` for forward
compatibility: `Body`, `FullContext`, `PublishResponse`, `SearchHit`,
`SearchResponse`, `Signature`, `RegistryState`, `WebhookEvent`, `StepEvent`.
ACDP 0.3 additions ride on the typed surface as verbatim members:
`RegistryState.lifecycle_events` (list of raw event dicts, absent → `None`)
plus the `is_retracted` convenience predicate on both `RegistryState` and
`FullContext` (RFC-ACDP-0013 §7.2: `retracted` dominates), and
`FullContext.lineage_head_receipt` (raw dict, `/current` only).
These track the [context-body](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0002-context-body.md)
and [publish](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0003-publish.md)
shapes — they are a convenience mirror, not the normative schema (the JSON
Schemas live in the spec repo).
