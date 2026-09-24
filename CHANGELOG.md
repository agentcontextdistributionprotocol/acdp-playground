# Changelog

Notable changes to the ACDP stack as observed from the playground.
Tracks cross-repo work — playground, control plane, registry, SDK —
so operators reading any one repo can see the system-wide picture.

## 2026-09-24 — `acdp` 0.14.1: receipts now bind the served body (RFC-ACDP-0010 §8 step 3)

Catches the playground up to `acdp` **0.14.1**, the version both sibling
binaries already build against (`acdp-registry-rs` `Cargo.toml`,
`acdp-control-plane` `package.json`). The playground was the last repo in the
family still coding against 0.8.3. Pin moved `acdp>=0.8.3` → `acdp>=0.14.1`;
`uv.lock` resolves 0.14.1 and nothing else moved. abi3 wheels cover every
platform CI runs on, so this is a re-lock, not a rebuild — no Rust toolchain,
no `make build-sdk`.

The version jump is large and the Python-visible delta is small: the `acdp`
module is offline-only JSON-over-FFI with no `RegistryClient` and no
networking, so every `feat(client)!` / `feat(server)!` change in the range is
structurally invisible to a Python caller. Exactly three things break or add
surface, and one of them is a required-positional-argument break.

### SDK

- **`AcdpVerifier.verify_receipt` gained `body_json` as argument #2** (arity
  5 → 6) and now runs `RegistryReceipt::cross_check_body` — RFC-ACDP-0010 §8
  step 3: the receipt's `lineage_id` / `origin_registry` / `created_at` MUST
  equal the served body's. All **seven** call sites in this repo migrated.
  Four pass a genuinely retrieved body; **S23**, **S27** and **S32**'s offline
  half had no body at all
  and now build one through `synthesize_retrieval_body`, which overlays the
  four registry-assigned fields onto a real signed publish request rather than
  hand-writing a second implementation of the body schema.
- **`CtxId::parse` replaced the bare `CtxId` newtype** in
  `build_publish_request(derived_from=)`, `verify_lineage_head_receipt`'s
  `expected.head_ctx_id` and `verify_receipt`'s `expected_ctx_id`, so every
  identifier must be `acdp://<lowercase-DNS-authority>/<v4-uuid>` with correct
  version and variant nibbles. Already satisfied: `acdp_client.identifiers`
  mints conformant synthetic ids repo-wide.
- **New — `AcdpVerifier.verify_ctx_id_binding(body_json, expected_ctx_id)`**
  (RFC-ACDP-0006 §4.1 step 7). Pinned in the surface guard here; adopted on the
  retrieval path below.

### Client — every retrieval is now bound to the `ctx_id` it asked for

`ctx_id` is registry-assigned and sits outside both `content_hash` and the
producer signature (RFC-ACDP-0001 §5.7). On the receipt-less retrieval path —
most of the playground's traffic — that made the requested-vs-served comparison
the **only** thing standing between "the context I asked for" and any other
validly-signed body from the same producer. Nothing was performing it.

- `AcdpClient` gained a single retrieval chokepoint. `retrieve`, `retrieve_raw`,
  `retrieve_body` and `_lifecycle` were four *parallel* implementations, each
  with its own send/retry/raise; they now share `_get_full_context`, which
  performs the §4.1 step 7 binding before returning. `lineage` and `current`
  share `_get_lineage`, which validates the served id's form (those routes are
  keyed by `lineage_id`, so there is no requested `ctx_id` to compare against).
- The shared helper returns **raw JSON**; each caller does its own validation.
  That is load-bearing, not stylistic: `retrieve_raw` feeds
  `build_supersede_request`, which needs the registry's exact bytes, and a
  model round-trip would inject explicit nulls for unset optionals and break
  every supersession scenario without failing a single binding test.
  `test_retrieve_raw_returns_byte_identical_json` is the regression guard.
- New typed `CtxIdBindingError` with `.reason` — `mismatch` (both ids parse and
  differ), `malformed` (either fails `CtxId::parse`; the SDK parses both sides)
  or `unverifiable` (a body with no `ctx_id`, which **fails closed**, mirroring
  the control plane's 502 `CONTEXT_BINDING_UNVERIFIABLE`). The reason matters
  because `CtxIdBindingError` is a `RuntimeError` and so sits inside
  `_sdk_guard.SDK_REJECTIONS` next to `ValueError`: a bare raise cannot tell
  substitution apart from a broken identifier.
- Enforcement is **on by default**, with an explicit, greppable
  `verify_binding=False` opt-out per call on `retrieve_raw` and client-wide on
  the constructor. Nothing in the playground opts out.

### Scenarios

- **S23 — receipt tamper** grows from six adversarial cases to **eight** here,
  and to nine once the retrieval binding below lands. The
  two new ones are only expressible because the verifier now sees the body:
  a receipt whose `lineage_id`, or whose `origin_registry`, disagrees with the
  body served alongside it. Both receipts are internally consistent, so nothing
  earlier in the §8 sequence catches the substitution. Each asserts on the
  *named* field, not on a bare raise.
- **S27 — registry receipt-key rotation** now models **two** bodies, one per
  receipt, differing only in `created_at` — because a registry re-attesting
  after a key rotation serves a re-attested body, and §8 step 3 is exactly the
  check that binds the two. A new case lifts the historical receipt onto the
  current receipt's body and proves it fails closed under a key that resolves
  fine.
- **S32 — key revocation** mints its victim receipt and body as a pair for the
  same reason.
- **S23** gains that ninth case, `substituted_body`: a registry answers a
  retrieval with a *different*, entirely valid context. No receipt is involved,
  so none of the §8 gates apply — it drives the real `AcdpClient` and asserts
  the transport refuses it with `reason == "mismatch"`.

### Tests

- `tests/test_sdk_surface.py` pins `verify_receipt` at `(6, 6)` and registers
  `verify_ctx_id_binding` at `(2, 2)`. This is the guard that made the break
  loud: before it, five of S23's six checks recorded a `TypeError` from the
  arity change and scored it as the receipt correctly failing closed.
- `test_s23_rejects_body_binding_mismatch` and
  `test_s27_two_receipts_bind_their_own_bodies` — the positive and negative
  halves of §8 step 3 being live.
- `tests/test_client_ctx_binding.py` — the §4.1 step 7 matrix: every retrieval
  method bound, the three reasons kept apart, the bare-body route shape, the
  opt-out, cross-registry reads still accepted, and `retrieve_raw`'s
  byte-exactness.
- `probe_served_ctx_id_binding` joins `REGISTRY_PROBES`, with a `MockTransport`
  drift counterpart that serves a substituted body and asserts the probe fails.

### Conformance probes — three registry contracts nothing was asserting

The investigation behind this bump surfaced three externally-observable
contracts the siblings enforce today that **no scenario would notice
regressing**: in each case the playground's own behaviour is identical whether
the gate exists or not. All three join `REGISTRY_PROBES`, each with a
`MockTransport` counterpart that serves the wrong answer and asserts the probe
raises.

- **`probe_media_type_gate`** — RFC-ACDP-0007 §4.1 on `POST /contexts`, both
  directions. `text/plain` → **415** `unsupported_media_type`, asserted on the
  envelope code rather than the status alone so a proxy answering 415 cannot
  pass for a conformant registry; `application/json; charset=utf-8` accepted
  (parameters are not part of the decision); and a request with **no**
  `Content-Type` accepted **on this route specifically**. The accept half is
  the load-bearing one: `AcdpClient` labels every request `application/json`,
  so a registry narrowing its accept-set to `application/acdp+json` would break
  every publish, retract and republish at once, and a reject-only probe would
  stay green through it. The header-less assertion is scoped to the data plane
  on purpose — `/auth/*` rejects an absent header with 415, a documented
  per-route divergence — so "absent is always accepted" is a contract that does
  not exist and is not pinned. Its two accept-side publishes share one
  `Idempotency-Key`, so the probe adds at most one context to the registry
  however often it runs.
- **`probe_interim_revocation_type_rejected`** — RFC-ACDP-0014 §10: a new
  publish typed `acdp:key-revocation` → **400** `schema_violation`. S32 already
  publishes the modern `key-revocation` spelling, so the retirement regressing
  is invisible from inside the playground. The probe publishes a schema-*valid*
  revocation body under the interim type, because a malformed one answered 400
  `schema_violation` long before §10 existed and would pass green against a
  registry with no retirement gate at all; for the same reason the rejection
  must name the offending type. Scoped to registries advertising ≥ 0.5.0 —
  below that line §10 requires the interim form to be accepted as an opaque
  custom type.
- **`probe_anchors_require_0_5_0`** — RFC-ACDP-0016 §14: `anchors` carried
  under a declared `acdp_version` below 0.5.0 → **400** `schema_violation`. S33
  publishes only the accepted side, so this is the gate it silently depends on.

A registry that answers **201 where a gate should answer 400 fails the probe**.
Only genuinely optional surface — an unadvertised profile, or a spec line below
the one that introduced the rule — is allowed to report a skip.

### Docs

- `docs/testing-and-conformance.md` — the probe table is now complete (all
  three groups: registry core, the 0.3.0 endpoint contracts, the control
  plane), documents the three new probes and the skip-vs-fail rule, and gains a
  **Synthetic-identifier sweep** section for `tests/test_identifiers.py`: the
  repo-wide guard that keeps ids like `acdp://r/1` — shapes no registry could
  assign, which sat green for releases because the SDK only began parsing
  strictly in 0.14.x — from growing back.
- Four prose sites that cited a version as if it were current now name it as
  historical: the `Producer::new_version_from` fix (SDK 0.8.3) in `README.md`
  and `docs/scenarios.md`, and the SSRF-policy and JCS-canonicalizer
  delegations (acdp-py 0.2.0) in `README.md`. The delegations are unchanged —
  only the phrasing, which read as though 0.2.0 were the pin.

### Notes

- **No wheel-ABI change.** It is tempting to assume a six-minor-version jump
  dragged pyo3 along with it. It did not: `pyo3 0.29` with `abi3-py39` first
  shipped in `acdp` **0.8.2**, one release *before* the pin this bump replaces.
  Settled at the binary level rather than from a manifest — `strings` on the
  published wheels reports `pyo3-0.22.6` for 0.8.1 and `pyo3-0.29.2` for 0.8.2,
  0.8.3 and 0.14.1 alike. So the old pin already carried the current pyo3, this
  bump carries no supply-chain argument of its own, and none should be claimed
  for it.
- Three items are the whole breaking-or-new Python surface, but two additive
  semantic deltas also reach a caller without being able to break one:
  `EmbeddedContent` gained an optional `content_hash`, so `data_refs` JSON that
  0.8.3 rejected is now accepted; and a malformed `derived_from` identifier now
  raises `ValueError` where 0.8.3 raised `RuntimeError` (both are inside
  `_sdk_guard.SDK_REJECTIONS`, so no assertion changes meaning).

## 2026-06-10 — Documentation set for the playground (`docs/`)

Adds a structured `docs/` tree that the website sync publishes as the
**/playground** section of [agentcontextdistributionprotocol.io](https://agentcontextdistributionprotocol.io)
(via `notify-website.yml`). The docs cover **only what is unique to the
playground** — the scenario catalog, the run lifecycle, the SSE API, the agent
abstractions, and the thin `acdp_client` wrapper — and **reference** the sibling
projects (`acdp-rs`, `acdp-registry-rs`, `acdp-control-plane`, the spec/RFCs) for
everything they canonically own, rather than re-documenting it.

### Docs

- **`docs/README.md`** — index, scope note, and a *Related projects* map linking
  each topic (signing, error envelope, SSRF policy, token flow, tenancy, config)
  to the repo that owns it.
- **`docs/architecture.md`**, **`getting-started.md`**, **`scenarios.md`**,
  **`http-api.md`**, **`client-sdk.md`**, **`agents.md`**, **`configuration.md`**,
  **`deployment.md`**, **`testing-and-conformance.md`** — one page per surface,
  cross-linked, with sibling/spec references in place of duplicated detail.

### README

- Added a **Documentation** section pointing at `docs/` and the published site,
  and a **Related projects** table so readers land on the right repo.

## 2026-06-08 — Conformance hardening: live-stack validation + CP #51 / did:web coverage

Adds a live-stack conformance layer so the playground's asserted contracts are
validated against the **real** registry/CP binaries, not just `httpx.MockTransport`
— the gap that let the reserved-tenant `422 → 400` mock drift go green. Also
fills the previously-unexercised CP #51 surfaces and adopts the acdp-py 0.3.0
did:web helpers.

### Live conformance

- **`playground/conformance.py`** — shared probes asserting real contracts:
  reserved-tenant 400, `application/acdp+json` error envelope, 1 MiB ingest 413,
  `GET /events` server-side limit cap, revocation-feed shape, admin pinned-key
  reload, and capability DTO `ecdsa-p256` acceptance (CP #51).
- **`tests/live/`** — pytest suite behind the `live` marker, skipped unless
  `ACDP_LIVE_STACK` is set; SSE de-dup behind `ACDP_LIVE_SSE` (Redis-only).
  Validated against the real registry binary (reserved-tenant 400, 404 envelope,
  1 MiB 413).
- **`smoke_test.py --live`**, `make test-live` / `make smoke-live`, and a manual
  `workflow_dispatch` CI job that boots registry + CP and runs the suite.

### Scenarios + bridge

- **S21 — P-256 capability declaration** (offline): emits the `ecdsa-p256`
  capability declaration CP #51's DTO now accepts and self-verifies the signature.
- **`ControlPlaneClient.events` / `.declare_capability`** bridge methods
  (`GET /events`, `POST /capabilities`), with offline unit coverage.

### Client / SDK

- **did:web helpers re-exported** from `acdp_client` (`AcdpDid`,
  `AcdpDidDocument`, `DidResolutionError`, acdp-py 0.3.0). S19 now resolves its
  emitted `did.json` through the same Rust consumer gate the CP uses.

## 2026-06-07 — Playground sibling sync, round 5 (delegate JCS + SSRF to the SDK)

Consumes `acdp-rs` PR #32, which exposed the JCS canonicalizer and the SSRF
screen through the Python SDK (`acdp-py` 0.2.0: `AcdpCanonicalizer`,
`AcdpSsrfPolicy` / `SsrfRejected`, with a stable `SsrfReason` taxonomy in the
Rust core). The playground now delegates to those instead of maintaining its
own copies. Requires a rebuilt wheel (`make build-sdk`), now pinned
`acdp>=0.2.0`.

### Client / SDK

- **Deleted `acdp_client/jcs_numbers.py`** (~130 lines). JCS canonicalization
  + content hashing now run in Rust via `acdp.AcdpCanonicalizer`; the
  `can-011` RFC vectors gate the binding through `tests/test_jcs_vectors.py`
  instead of a second pure-Python implementation.
- **Shrank `acdp_client/safe_http.py`** to the orchestration the Rust core
  doesn't own: DNS resolution, the mixed-answer rejection loop (plan D3), the
  `httpx` fetch with same-authority-redirect + size caps, and `content_hash`
  verification. The forbidden IP-range tables, the v4-mapped/NAT64 coercion,
  and the scheme/redirect predicates are gone — `check_url`, `ip_is_forbidden`,
  `same_authority`, and `screen_host` now delegate to `acdp.AcdpSsrfPolicy`.
  Public names are unchanged so `s16_dataref_ssrf.py` and
  `AcdpClient.fetch_data_ref` don't move.
- **Reason taxonomy** on `SsrfError.reason` now follows the Rust `SsrfReason`
  codes: `169.254.*` / IPv6 link-local / NAT64 → `imds` (was `link_local` /
  `nat64` / `ipv6_special`), `0.0.0.0` → `multicast_or_reserved`, ULA →
  `private`, `http://` → `non_https`. The userinfo guard
  (`forbidden_userinfo`) stays in Python — the Rust `check_url` does not
  reject credentials in the authority (filed as an acdp-rs follow-up).

### Tooling

- `smoke_test.py` JCS check drives `AcdpCanonicalizer`; tests repointed.
- Rebuilding to 0.2.0 also clears the prior **stale-wheel** failures
  (`build_publish_request(data_refs=…)` / `expected_lineage_id`): full suite
  now **172 passing**, smoke **14/14** (previously 3 failing + smoke aborting).

## 2026-06-06 — Playground sibling sync, round 4 (reserved tenant + federation)

Tracks `acdp-control-plane` #50, which brought the control plane to
federation parity with the updated `acdp-rs` / `acdp-registry-rs`: a
cross-issuer revocation poller, a reserved-tenant guard, multi-tenant
fail-fast on startup, and a now-required audience binding per trusted
issuer. The CP-internal poller and the per-issuer audience requirement
need no playground code; the reserved-tenant rule and the config coupling
do. No SDK rebuild required.

### Client / SDK

- **Reserved-tenant guard.** `acdp_client.identifiers.reject_reserved_tenant`
  (plus `RESERVED_TENANT` / `is_reserved_tenant`) refuses the `default`
  sentinel as an *asserted* tenant. It is the silent column default for
  untenanted rows, so asserting it via `X-Tenant-Id` or a signed `tenant`
  claim would alias the entire untenanted bucket — a cross-boundary
  read/write. `AcdpClient` calls it at construction (`tenant_id="default"`
  fails fast) and the control-plane bridge calls it before stamping the
  header, so a caller learns locally instead of via a server 422/403.
  Untenanted access stays reachable only through the *absence* of an
  assertion. Mirrors the registry's `reject_reserved_tenant`
  (acdp-registry-core `c988ea4`) and the CP `AuthGuard` (#50).

### Scenarios + tooling

- **S20 — reserved-tenant rejection.** Fully offline: the standalone guard
  blocks `default` and passes `None` / real tenants through; the client
  constructor and CP bridge both refuse `default`. The live wire contract
  (registry 400 `schema_violation` / CP 403 `not_authorized`) is asserted
  against a mock transport in `tests/test_reserved_tenant.py`.
- **smoke_test.py** grows a reserved-tenant client-guard check (14 total).

### Config / control plane

- **Multi-tenant fail-fast.** `docker-compose.full.yml` and `.env.example`
  now warn that setting `TENANT_AGENTS` (or a tenant-bound key) while
  `AUTH_REQUIRE_TENANT=false` refuses CP startup — populate
  `CONTROL_PLANE_TENANT_AGENTS` only alongside
  `CONTROL_PLANE_AUTH_REQUIRE_TENANT=true`.
- **Federation knobs.** Documented the CP's new `TRUSTED_ISSUERS` (audience
  now required per entry) and `REVOCATION_FEEDS` env, wired through as
  empty-by-default `CONTROL_PLANE_TRUSTED_ISSUERS` /
  `CONTROL_PLANE_REVOCATION_FEEDS` overrides for the single-CP demo.

## 2026-06-03 — Playground sibling sync, round 3 (wire conformance)

Tracks the P0/P1 remediation + RFC-ACDP-0007 §5 wire-conformance wave that
landed in the registry (`acdp-registry-rs` #24/#25/#26) and control plane
(`acdp-control-plane` #48/#49) within a day of the round-2 sync. The
companion `acdp-rs` changes (`8d46074` P-256 multicodec fix, `aafa92e`
publish-tenant threading / SSRF-safe client / DID hardening) are core +
registry-side and leave the Python binding surface unchanged, so no SDK
rebuild is required.

### Client / SDK

- **§5 error-code model.** `acdp_client.models.ERROR_CODES` enumerates the
  machine codes the registry now emits (`invalid_signature`,
  `unsupported_algorithm`, `key_resolution_failed` / `key_resolution_unreachable`,
  `not_implemented`, …); `SIGNATURE_ERROR_CODES` groups the credential/
  algorithm subset. `data_ref_hash_mismatch` is kept distinct from
  `hash_mismatch`.
- **Typed wire errors.** `NotAuthorizedError` (the `not_authorized` code,
  now **403** per registry #24) and `PayloadTooLargeError` (**413** from the
  outer body-limit layer, now carrying `application/acdp+json` per #26) join
  `SupersededError` under `AcdpHTTPError`. The 401-only re-mint-and-retry is
  documented as deliberate — a 403 is terminal.
- **Audience telemetry.** `CachedToken.aud` peeks the JWT `aud` claim (now
  bound to the issuing authority on both siblings) and logs it on mint;
  verification stays with the issuer.

### Scenarios + tooling

- New scenarios **S18** (idempotent-publish replay; degrades gracefully) and
  **S19** (offline did:web P-256 conformance — the JWK-only `JsonWebKey2020`
  the CP #49 resolver accepts).
- **S17** documents the tenant-continuity dimension (cross-tenant
  supersession collapses to the same `not_found` shape — no oracle).
- `smoke_test.py` grows to 13 checks (idempotent replay, typed 403/413).
- New tests: `test_idempotency.py`, `test_scenarios_round3.py`, plus
  framework-413 cases in `test_error_envelope.py`.

### Config / control plane

- The control-plane bridge parses the CP's ACDP error envelope (#49) and
  logs `error.code`/`reason`.
- `docker-compose.full.yml` + `.env.example` document the new CP env knobs
  (`JWT_AUDIENCE`, `AUTH_REQUIRE_TENANT`, `INGEST_MAX_BODY_BYTES`,
  `INGEST_MAX_JSON_DEPTH`, `INGEST_STRICT_TENANT`, `WEBHOOK_SSRF_*`) with
  secure-but-demo defaults; registry configs note the new loopback-bind
  constraint (#24).

## 2026-06-02 — Playground sibling sync, round 2 (security remediation)

Closes the gap opened by the P0/P1 remediation + wire-conformance wave
that landed across the siblings hours after the V2 sync (`#12`): consumer
SSRF enforcement (`acdp-rs` #29), producer-ownership on supersession
(`acdp-registry-rs` `34aee21`), the RFC-ACDP-0007 error envelope
(`acdp-registry-rs` `18f73de`), RFC-8785 numeric canonicalization
(`acdp-rs` `b79a1eb`), and the round-3 RFC clarifications.

### Client / SDK

- **Consumer SSRF guard.** New `acdp_client.safe_http` screens
  `data_refs[].location` fetches: https-only, all resolved IPs validated
  against private/loopback/IMDS/ULA/NAT64/v4-mapped ranges with
  mixed-answer rejection, same-authority (scheme+host+effective-port)
  redirects, and size/timeout caps. `AcdpClient.fetch_data_ref(...)`
  verifies `content_hash` (`DataRefHashMismatch`). The Rust SDK's guard
  lives in its `RegistryClient`, which the playground's `httpx` client
  does not use — so this is enforced in pure Python (RFC-ACDP-0008 §4.9).
- **Error wire envelope.** `AcdpHTTPError` now parses the RFC-ACDP-0007 §4
  `application/acdp+json` envelope into `.code` / `.reason` / `.details`;
  a rejected supersession raises `SupersededError` carrying the
  `details.reason` subtype. `Accept: application/acdp+json` is advertised.
- **JCS numeric reference.** `acdp_client.jcs_numbers` is a tested
  pure-Python ECMAScript Number::toString (RFC 8785 §3.2.2.3) + canonical
  serializer, validated against the RFC's `can-011` vectors.
- **Cooperative token throttling.** `TokenManager` honours `429 +
  Retry-After` on the challenge/token mint path with one capped retry; the
  RFC 9110 parser moved to `acdp_client.retry_after` (re-exported from
  `playground.retry_after`).
- **Identifier hygiene.** `acdp_client.identifiers` validates
  `origin_registry` as a bare DNS hostname (RFC-ACDP-0002 §3.1).

### Scenarios + tooling

- New scenarios **S16** (offline consumer-SSRF-guard demo) and **S17**
  (supersession authorization / lineage-takeover prevention; degrades
  gracefully without the registry).
- `smoke_test.py` grows to 11 checks (adds JCS numeric vectors, SSRF
  guard, supersession-error parsing).
- 30+ new unit tests across SSRF, error envelope, JCS vectors,
  identifiers, challenge Retry-After, and the round-2 scenarios.

### Config / control plane

- Registry configs gain `limits.challenge_rate_per_minute` and an
  `auth.admin_tokens` entry (pinned-key reload parity with the CP).
- The CP bridge gains `domain_packs()` (`GET /domain-packs`).

## 2026-06-01 — Playground V2 sibling sync

The playground now exercises the features that landed across the RFC,
the Rust SDK, the registry, and the control plane since late May. See
`plans/2026-06-01-playground-sibling-sync.md` for the full plan.

### Client / SDK

- **ECDSA-P256 signing.** `acdp_client.signing` abstracts over
  `AcdpProducer` (Ed25519) and `AcdpP256Producer` (P-256); the token
  manager posts the matching `algorithm` to `/auth/token` and the
  verifier dispatches to the right path. `make build-sdk` rebuilds the
  compiled `acdp` extension to pick up the new producer.
- **Cursor pagination.** `AcdpClient.search(cursor=...)` +
  `search_all(...)`; the latter continues through an empty-but-cursored
  page (RFC-ACDP-0005 §2.3) and surfaces `invalid_cursor` /
  `cursor_expired` as `CursorError`.
- **Token revocation.** `TokenManager.revoke(...)` (RFC 7009) +
  unverified `tenant`/`jti` claim surfacing for telemetry.
- **Tenant header policy.** `AcdpClient(tenant_id=, tenant_header_mode=)`
  — `X-Tenant-Id` is a fallback only and is suppressed for
  bearer-authenticated requests so it never contradicts the JWT claim.
- **Extended body fields.** Agents thread `data_refs` / `data_period` /
  `expires_at`; supersession uses `expected_lineage_id` via
  `build_supersede_request`.

### Control plane bridge

- Forwards `X-Tenant-Id` + `X-ACDP-Event-Id` on webhooks and run
  notifications; honours a cooperative `Retry-After` (RFC 9110).
- Operator surface: `introspect` (RFC 7662), `revocations` feed,
  `reload_pinned_keys` — gated on `CONTROL_PLANE_ADMIN_TOKEN`.
- `docker-compose.full.yml` + `make up-full` run the CP as a
  first-class service (DB-less memory mode).

### Scenarios + tooling

- New scenarios **S9–S15**: P-256 publish, tenant isolation, revocation,
  key rotation + admin reload, policy/authz, domain-pack gating, and
  supersession with a lineage guard.
- `gen_keys.py --algorithm ecdsa-p256` emits SEC1/JWK/`verificationMethod`;
  `pinned_keys_diff.py` encodes algorithm + validity windows.
- Registry configs gain `auth.tenant_agents`, pinned-key rotation
  windows, and documented EdDSA / revocation-feed blocks.
- `smoke_test.py` grows to 8 checks (adds P-256, JCS float stability,
  extended body fields); 44 new unit tests cover signing, cursor
  pagination, tenant headers, revocation, Retry-After, pinned-key
  windows, and the control-plane bridge.

## 2026-05-26 — Auth, security, and tenancy hardening

A coordinated pass across the control plane and the registry that
closes a long list of audit findings under one heading. Every item
below is shipped on `main` of the relevant repo; this entry is a
flat summary, not a roadmap.

### Authentication

- **JWT validation in the control plane's `AuthGuard`.** Until now the
  guard validated only API keys; the entire JWT issuance surface
  (challenge / token / introspect / revoke / cross-issuer) was tested
  but never consumed by the request path of the application
  controllers. The guard now dispatches on token shape (3-segment
  JWT vs opaque api key), validates via `CrossIssuerValidator`, and
  populates `request.actorDid` from the `sub` claim. A JWT-shaped
  token that fails verification is rejected outright — no
  fall-through to API-key matching (which would have been a silent
  oracle).

- **EdDSA signing + JWKS endpoint on both control plane and registry.**
  Opt-in via `JWT_SIGNING_ALG=EdDSA` + `JWT_PRIVATE_KEY_PEM`. The
  public key is published at `GET /.well-known/jwks.json` so
  federated peers can verify without out-of-band secret distribution.
  Trusted-issuer wire format extended to accept `EdDSA + jwks_url`
  alongside the HS256 shared-secret form. `kid` lookup with TTL
  cache, error caching, in-flight coalescing, and malformed-entry
  tolerance.

- **ECDSA-P256 acceptance on the registry's `/auth/token`.** The
  publish path already accepted P-256; the auth handshake hard-
  rejected it. Algorithm-downgrade defense kept; verifier dispatches
  on `req.algorithm`.

- **Tighter throttle on credential endpoints.** `/auth/challenge`
  and `/auth/token` (control plane) carry a 20-req/min/IP override
  on top of the 200/min global. Defends against nonce-grinding,
  credential-stuffing, and DID-resolver DoS.

- **Subject-match gate on `/auth/token/revoke`.** Admin api keys
  (listed in `AUTH_ADMIN_API_KEYS`) can revoke any JTI; JWT-
  authenticated callers can revoke only tokens whose `sub` matches
  their own DID. Mirrors the registry's `owner_of(jti) ==
  caller_did` semantics that was already in place.

- **Revocation list consulted by introspect.** Previously
  `CrossIssuerValidator.verify()` only checked signature/issuer/
  expiry; revoked tokens still came back as `{active:true}` from
  `/auth/introspect`. The validator now optional-injects the
  revocation repository and rejects local-issued tokens whose JTI
  has been revoked. Trusted-peer tokens still bypass the local list
  — peers own their own revocation feeds (see below).

### Policy engine

- **OPA / Rego backend** alongside the static-rules engine. Opt-in
  via `POLICY_BACKEND=opa`; reference Rego corpus mirrors the
  static rules so deployments can switch transparently. Caching
  wrapper preserved on top of either backend.

- **`@CheckPolicy` mounted on runs + contexts.** Previously only
  `capability.declare` carried the decorator. List, get, lineage,
  events, and run-complete are now gated by `run.read` / `run.start`;
  context retrieve is gated by `context.retrieve`. Static-rules
  decider was adjusted so retrieve-without-visibility allows
  authenticated requests through (the service layer enforces
  visibility post-fetch — the guard runs before the resource is
  loaded).

### Multi-tenancy

- **`tenant_id` column on the registry's `contexts` table.** PG +
  SQLite migrations; existing rows backfill to `'default'`. New
  composite indexes on `(tenant_id, created_at)` and
  `(tenant_id, lineage_id)` keep tenant-filtered queries off
  seqscans.

- **Tenant filter on retrieve / search / lineage / current /
  retrieve-body / admin-list.** Same opt-in semantics across all
  read paths: request without `X-Tenant-Id` returns the V0
  unfiltered view; request with the header narrows to the caller's
  tenant. Mismatch returns the same 404 shape as a non-existent row
  (no oracle).

- **JWT `tenant` claim — authoritative.** Control plane mints the
  claim from a `TENANT_AGENTS=tenant:did,...` config. Both control
  plane's `AuthGuard` and the registry's read handlers prefer the
  claim over the `X-Tenant-Id` header; if both are present and
  disagree → 403 (control plane) / `AuthChallenge` error
  (registry). A bearer can no longer assert a tenant it was never
  issued for.

- **Redis-backed quota middleware.** `TENANT_QUOTAS=tenant:action=N/min`
  wire format. Atomic INCR + EXPIRE-NX via a Lua script defends
  against the race that would have reset the window on every call.
  Fail-open on Redis outage with a warn log.

### Cross-issuer federation

- **`GET /auth/revocations` on the control plane** publishes a paged
  feed of recent revocations keyed by `revoked_at_ms`. Admin-gated.
  Strict-greater-than cursor semantics keep pages non-overlapping;
  secondary sort on `jti` keeps pagination deterministic when
  multiple revocations share a timestamp.

- **Cross-issuer revocation poller on the registry.** One background
  task per peer feed configured under `[[auth.revocation_feeds]]`.
  Polls the bearer-gated feed, writes propagated entries into the
  local revocation store, retries on transport / decode / store
  failures. With both halves running, a token revoked at the issuer
  is rejected at every consuming registry within one poll interval
  without shared state.

### Cleanup

- `auth.guard.spec.ts` slice-mismatch failures fixed.
- `ingest.service.spec.ts` TS errors fixed.
- OpenAPI/Swagger annotations on the new auth endpoints.
- Pinned-keys diff CLI for syncing the registry's `[playground]
  pinned_keys` block to the control plane's
  `CONTROL_PLANE_PINNED_KEYS` env.
- Token-manager telemetry: structured logs distinguish proactive-
  refresh from reactive-401-refresh so operators can spot
  abnormally short token lifetimes (clock skew, secret rotation).
