"""Async httpx client for one ACDP registry.

Crypto lives in ``AcdpProducer`` (the acdp-py Rust SDK). This class
handles only HTTP: routing, headers, error handling.

Optional auth — when an :class:`acdp.AcdpProducer` and an
:class:`acdp_client.token_manager.TokenManager` are supplied, the
client transparently:

* injects ``Authorization: Bearer <token>`` on each request,
* refreshes the token proactively before expiry,
* retries a single time on a 401 (invalidating the cached token
  first) so a stale token doesn't leak into the caller.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, AsyncIterator, Awaitable, Callable, Literal
from urllib.parse import quote

import httpx

from acdp_client.identifiers import reject_reserved_tenant
from acdp_client.models import (
    CURSOR_ERROR_CODES,
    Body,
    CursorError,
    FullContext,
    PublishResponse,
    SearchHit,
    SearchResponse,
    parse_error_envelope,
)

if TYPE_CHECKING:
    from acdp_client.safe_http import SsrfPolicy
    from acdp_client.signing import Producer
    from acdp_client.token_manager import TokenManager

TenantHeaderMode = Literal["fallback", "always", "never"]


class AcdpHTTPError(RuntimeError):
    """Raised when a registry returns a non-2xx response.

    Parses the RFC-ACDP-0007 §4 error envelope
    (``{"error":{"code","message","details"}}``, served as
    ``application/acdp+json``) when present, exposing ``.code`` /
    ``.reason`` / ``.details`` so callers can branch on the machine
    code rather than scraping the message string.
    """

    def __init__(
        self,
        status: int,
        body: str,
        url: str,
        *,
        code: str | None = None,
        message: str | None = None,
        details: dict | None = None,
    ):
        super().__init__(f"{status} from {url}: {(message or body)[:400]}")
        self.status = status
        self.body = body
        self.url = url
        self.code = code
        self.details = details or {}

    @property
    def reason(self) -> str | None:
        """The ``details.reason`` subtype, when the envelope carried one."""
        reason = self.details.get("reason")
        return reason if isinstance(reason, str) else None


class SupersededError(AcdpHTTPError):
    """A ``supersedes`` request was rejected (RFC-ACDP-0007 ``superseded_target``).

    ``reason`` distinguishes the subtype: ``not_found`` (absent, not owned by
    the requester, *or* a cross-tenant successor — all collapse to one
    no-existence-oracle shape, registry #24),
    ``cross_registry_supersession_unsupported``, ``lineage_mismatch``,
    ``already_superseded``, etc.
    """


class NotAuthorizedError(AcdpHTTPError):
    """Authenticated but not permitted (RFC-ACDP-0007 ``not_authorized``).

    The registry returns **403** for this as of acdp-registry-rs #24 (it was
    formerly 401). This is distinct from a bare 401 — which means the *token
    itself* was rejected (expired / revoked / unknown) and triggers one
    transparent re-mint-and-retry in :meth:`AcdpClient._retrying`. A 403 is
    terminal: re-minting the same identity will not change the outcome, so the
    client surfaces it immediately.
    """


class PayloadTooLargeError(AcdpHTTPError):
    """The request body exceeded the registry's size limit (HTTP 413).

    Emitted by the registry's outermost ``RequestBodyLimitLayer`` (registry
    #26). Because the rejection is produced by middleware *before* the handler
    runs, the body may be empty or carry only a short envelope — but it now
    carries ``application/acdp+json`` regardless. Maps to the registry's
    ``[limits] max_payload_bytes`` setting.
    """


class ImmutableFieldError(AcdpHTTPError):
    """A lifecycle request tried to supply or alter immutable body content
    (RFC-ACDP-0013 §6/§10, wire code ``immutable_field``, HTTP 400).

    Bodies are immutable; the retract/republish endpoints mutate **registry
    state only** — an envelope member that names body content is rejected
    before any transition runs.
    """


class InvalidLifecycleTransitionError(AcdpHTTPError):
    """The requested lifecycle transition conflicts with the context's current
    retraction state (RFC-ACDP-0013 §6 step 4, wire code
    ``invalid_lifecycle_transition``, HTTP 409): retract of an
    already-retracted context, or republish of a never-retracted one.
    Retryable only after the state changes.
    """


class InvalidLogProofError(AcdpHTTPError):
    """A transparency-log artifact failed verification (RFC-ACDP-0012 §9/§11,
    wire code ``invalid_log_proof``, HTTP 502).

    Only federation/consumer verification paths emit this — a registry never
    returns it from its own ``/log/*`` endpoints. Permanent: a bad proof will
    not verify on retry.
    """


def _build_http_error(r: httpx.Response) -> AcdpHTTPError:
    code: str | None = None
    message: str | None = None
    details: dict | None = None
    try:
        code, message, details = parse_error_envelope(r.json())
    except ValueError:
        # Framework-generated rejections (413/408, registry #26) may carry an
        # empty or non-JSON body while still advertising application/acdp+json.
        pass
    kwargs = dict(code=code, message=message, details=details)
    # 413 is a status-level signal that may arrive with no parseable envelope,
    # so branch on status before code.
    if r.status_code == 413:
        return PayloadTooLargeError(r.status_code, r.text, str(r.request.url), **kwargs)
    if code == "superseded_target":
        return SupersededError(r.status_code, r.text, str(r.request.url), **kwargs)
    if code == "not_authorized":
        return NotAuthorizedError(r.status_code, r.text, str(r.request.url), **kwargs)
    if code == "immutable_field":
        return ImmutableFieldError(r.status_code, r.text, str(r.request.url), **kwargs)
    if code == "invalid_lifecycle_transition":
        return InvalidLifecycleTransitionError(r.status_code, r.text, str(r.request.url), **kwargs)
    if code == "invalid_log_proof":
        return InvalidLogProofError(r.status_code, r.text, str(r.request.url), **kwargs)
    return AcdpHTTPError(r.status_code, r.text, str(r.request.url), **kwargs)


def _raise_for_status(r: httpx.Response) -> None:
    if r.is_success:
        return
    raise _build_http_error(r)


class AcdpClient:
    """Async httpx client for one ACDP registry.

    Construct with ``producer=...`` and ``token_manager=...`` to enable
    automatic bearer-token injection. Without those, the client behaves
    as an anonymous caller (which is fine for public-visibility
    contexts or for registries with ``anonymous_public_reads = true``).
    """

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        run_id: str | None = None,
        timeout: float = 30.0,
        http: httpx.AsyncClient | None = None,
        producer: "Producer | None" = None,
        token_manager: "TokenManager | None" = None,
        tenant_id: str | None = None,
        tenant_header_mode: TenantHeaderMode = "fallback",
    ):
        self._base = base_url.rstrip("/")
        self._static_bearer = bearer_token
        self._run_id = run_id
        self._http = http or httpx.AsyncClient(timeout=timeout)
        self._owns_http = http is None
        self._producer = producer
        self._token_manager = token_manager
        # Deployment-level tenant attribution. Per RFC-ACDP-0008 §6.4 the
        # `X-Tenant-Id` header is NEVER authoritative — it is only a
        # fallback for producer-signed (bearer-less) publishes. When a
        # bearer token is present the authoritative tenant rides in the
        # JWT `tenant` claim, so in "fallback" mode we suppress the header
        # to avoid a claim/header conflict (which the registry rejects).
        #   * fallback (default): send the header only when un-authenticated
        #   * always:             always send it (used to test conflict reject)
        #   * never:              never send it
        # The reserved `default` sentinel may never be *asserted* as a tenant
        # (registry + CP both reject it server-side, registry c988ea4 / CP #50).
        # Fail fast here so a caller learns locally instead of via a 403/422.
        reject_reserved_tenant(tenant_id)
        self._tenant_id = tenant_id
        self._tenant_header_mode: TenantHeaderMode = tenant_header_mode

    # ── lifecycle ────────────────────────────────────────────────────────

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AcdpClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # ── headers ──────────────────────────────────────────────────────────

    async def _bearer_token(self) -> str | None:
        """Resolve the bearer token for the next request.

        Order of precedence:
        1. Explicit ``bearer_token=`` constructor arg (static override).
        2. A live token from the :class:`TokenManager`, refreshed on
           demand.
        3. ``None`` — anonymous request.
        """
        if self._static_bearer:
            return self._static_bearer
        if self._producer and self._token_manager:
            cached = await self._token_manager.token_for(self._producer, self._base)
            return cached.token
        return None

    async def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        # Advertise the ACDP media type so a conforming registry serves the
        # RFC-ACDP-0007 §4 envelope (Content-Type: application/acdp+json).
        h = {
            "Content-Type": "application/json",
            "Accept": "application/acdp+json, application/json",
        }
        token = await self._bearer_token()
        if token:
            h["Authorization"] = f"Bearer {token}"
        if self._run_id:
            h["X-Run-Id"] = self._run_id
        tenant_header = self._tenant_header_value(authenticated=bool(token))
        if tenant_header is not None:
            h["X-Tenant-Id"] = tenant_header
        if extra:
            h.update(extra)
        return h

    def _tenant_header_value(self, *, authenticated: bool) -> str | None:
        """Decide whether to attach ``X-Tenant-Id`` to the next request.

        See the constructor for the policy rationale. The header is only
        a fallback signal; it is suppressed for authenticated requests in
        ``fallback`` mode so it can never contradict the JWT claim.
        """
        if self._tenant_id is None or self._tenant_header_mode == "never":
            return None
        if self._tenant_header_mode == "always":
            return self._tenant_id
        # fallback
        return None if authenticated else self._tenant_id

    async def _retrying(
        self,
        send: Callable[[dict[str, str]], Awaitable[httpx.Response]],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send a request once; on 401 with a managed token, invalidate
        + refresh + retry once.

        Idempotent for GET/PUT/DELETE and acceptable for POST since a 401
        means the prior call never reached the business-logic layer.

        Only **401** triggers the re-mint-and-retry: it means the token was
        rejected (expired / revoked / unknown), which a fresh token may fix.
        A **403** (``not_authorized``, registry #24 moved authz failures off
        401) is deliberately *not* retried — the identity is authenticated but
        forbidden, so re-minting the same token changes nothing; it falls
        through to ``_raise_for_status`` as :class:`NotAuthorizedError`.
        """
        headers = await self._headers(extra_headers)
        r = await send(headers)
        if r.status_code != 401 or not (self._producer and self._token_manager):
            return r
        # Cached token rejected — drop it and try once more.
        self._token_manager.invalidate(self._producer, self._base)
        headers = await self._headers(extra_headers)
        return await send(headers)

    # ── Publish ──────────────────────────────────────────────────────────

    async def publish(
        self,
        request_json: str,
        *,
        idempotency_key: str | None = None,
    ) -> PublishResponse:
        extra = {"Idempotency-Key": idempotency_key} if idempotency_key else None

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.post(
                f"{self._base}/contexts", content=request_json, headers=h
            )

        r = await self._retrying(send, extra_headers=extra)
        _raise_for_status(r)
        return PublishResponse.model_validate(r.json())

    # ── Retrieve ─────────────────────────────────────────────────────────

    @staticmethod
    def _encode_ctx(ctx_id: str) -> str:
        """URL-encode a ctx_id for path interpolation.

        ACDP ctx_ids look like ``acdp://<authority>/<uuid>`` — the
        embedded ``://`` and ``/`` break axum's `:ctx_id` single-segment
        capture if sent raw. ``quote(safe="")`` encodes every reserved
        character.
        """
        return quote(ctx_id, safe="")

    async def retrieve(self, ctx_id: str) -> FullContext:
        encoded = self._encode_ctx(ctx_id)

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(f"{self._base}/contexts/{encoded}", headers=h)

        r = await self._retrying(send)
        _raise_for_status(r)
        return FullContext.model_validate(r.json())

    async def retrieve_raw(self, ctx_id: str) -> dict:
        """Return the registry's full-context JSON verbatim (unparsed).

        Used when a downstream needs the exact body bytes the registry
        produced — e.g. ``build_supersede_request`` requires the previous
        body with its registry-assigned ``ctx_id``/``created_at`` and
        *without* the explicit nulls a re-serialized model would inject.
        """
        encoded = self._encode_ctx(ctx_id)

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(f"{self._base}/contexts/{encoded}", headers=h)

        r = await self._retrying(send)
        _raise_for_status(r)
        return r.json()

    async def retrieve_body(self, ctx_id: str) -> Body:
        encoded = self._encode_ctx(ctx_id)

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(
                f"{self._base}/contexts/{encoded}/body", headers=h
            )

        r = await self._retrying(send)
        _raise_for_status(r)
        return Body.model_validate(r.json())

    # ── Lifecycle (ACDP 0.3, RFC-ACDP-0013) ──────────────────────────────

    async def _lifecycle(self, ctx_id: str, action: str, event_json: str) -> FullContext:
        """POST a signed lifecycle event to ``/contexts/{id}/{action}``.

        The registry expects a closed envelope with exactly one member:
        ``{"event": <signed lifecycle event>}``. The event is spliced in as
        the caller-provided string, byte-verbatim — the registry hashes the
        event *as received* (RFC-ACDP-0013 §5), so the client never
        re-serializes what the producer signed.

        The producer's authentication is the event signature itself (like a
        publish); a bearer token is only consulted for read visibility.
        Returns the post-transition :class:`FullContext` (``registry_state``
        re-derived, the event appended to ``lifecycle_events``).
        """
        encoded = self._encode_ctx(ctx_id)
        request_body = '{"event":' + event_json + "}"

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.post(
                f"{self._base}/contexts/{encoded}/{action}",
                content=request_body,
                headers=h,
            )

        r = await self._retrying(send)
        _raise_for_status(r)
        return FullContext.model_validate(r.json())

    async def retract(self, ctx_id: str, event_json: str) -> FullContext:
        """Retract a context (mark-not-delete, RFC-ACDP-0013 §6).

        ``event_json`` is a signed lifecycle event object with
        ``event_type: "retracted"``, ``ctx_id`` equal to the target, and the
        producer (``actor == body.agent_id``) as signer. Raises
        :class:`InvalidLifecycleTransitionError` (409) when the context is
        already retracted and :class:`ImmutableFieldError` (400) when the
        request touches body content.
        """
        return await self._lifecycle(ctx_id, "retract", event_json)

    async def republish(self, ctx_id: str, event_json: str) -> FullContext:
        """Reverse a prior retraction (RFC-ACDP-0013 §6).

        ``event_json`` is a signed lifecycle event with
        ``event_type: "republished"``. Raises
        :class:`InvalidLifecycleTransitionError` (409) when the context was
        never retracted. Both events remain in the append-only history.
        """
        return await self._lifecycle(ctx_id, "republish", event_json)

    # ── Transparency log (ACDP 0.3, RFC-ACDP-0012) ───────────────────────

    async def log_checkpoint(self) -> dict:
        """``GET /log/checkpoint`` — the registry's signed tree head.

        Returned verbatim (unparsed dict) so the signed wire bytes reach
        ``AcdpVerifier.verify_log_checkpoint`` unaltered. 501
        ``not_implemented`` when the registry does not run a log.
        """

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(f"{self._base}/log/checkpoint", headers=h)

        r = await self._retrying(send)
        _raise_for_status(r)
        return r.json()

    async def log_proof(
        self,
        *,
        ctx_id: str | None = None,
        leaf_index: int | None = None,
        tree_size: int | None = None,
        first: int | None = None,
        second: int | None = None,
    ) -> dict:
        """``GET /log/proof`` — an inclusion or consistency proof (verbatim).

        Two mutually-exclusive modes (mixing them is a 400
        ``schema_violation`` server-side):

        * **Inclusion** — exactly one of ``ctx_id`` (consumer surface,
          visibility-gated) or ``leaf_index`` (auditor surface), plus an
          optional historical ``tree_size``. Verify with
          ``AcdpVerifier.verify_log_inclusion`` against a leaf you rebuilt
          yourself via ``build_log_leaf`` — never a leaf the registry echoed.
        * **Consistency** — ``first`` and ``second`` tree sizes. Verify with
          ``AcdpVerifier.verify_log_consistency`` against your own retained
          root.
        """
        params: dict[str, str | int] = {}
        if ctx_id is not None:
            params["ctx_id"] = ctx_id
        if leaf_index is not None:
            params["leaf_index"] = leaf_index
        if tree_size is not None:
            params["tree_size"] = tree_size
        if first is not None:
            params["first"] = first
        if second is not None:
            params["second"] = second

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(f"{self._base}/log/proof", params=params, headers=h)

        r = await self._retrying(send)
        _raise_for_status(r)
        return r.json()

    async def log_entries(self, start: int, end: int) -> dict:
        """``GET /log/entries?start=..&end=..`` — a leaf page (verbatim).

        0-based, start-inclusive, end-exclusive; the registry caps a page at
        256 entries — continue from ``start + len(entries)``. Each entry
        always carries ``leaf_index`` + ``leaf_hash``; the full ``leaf`` is
        present only where the requester could retrieve that context.
        """

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(
                f"{self._base}/log/entries",
                params={"start": start, "end": end},
                headers=h,
            )

        r = await self._retrying(send)
        _raise_for_status(r)
        return r.json()

    # ── Search ───────────────────────────────────────────────────────────

    async def search(
        self,
        q: str | None = None,
        *,
        context_type: str | None = None,
        domain: str | None = None,
        agent_id: str | None = None,
        tags: list[str] | None = None,
        derived_from: str | None = None,
        visibility: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
    ) -> SearchResponse:
        params: dict[str, str | int] = {}
        if q is not None:
            params["q"] = q
        if context_type is not None:
            params["type"] = context_type
        if domain is not None:
            params["domain"] = domain
        if agent_id is not None:
            params["agent_id"] = agent_id
        if tags:
            params["tags"] = ",".join(tags)
        if derived_from:
            params["derived_from"] = derived_from
        if visibility is not None:
            params["visibility"] = visibility
        params["limit"] = limit
        if cursor is not None:
            params["cursor"] = cursor

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(
                f"{self._base}/contexts/search", params=params, headers=h
            )

        r = await self._retrying(send)
        self._raise_cursor_error(r)
        _raise_for_status(r)
        return SearchResponse.model_validate(r.json())

    @staticmethod
    def _raise_cursor_error(r: httpx.Response) -> None:
        """Translate a 400 + cursor error code into :class:`CursorError`.

        RFC-ACDP-0007 §4 returns ``{"error": {"code": "...", ...}}``;
        ``invalid_cursor`` / ``cursor_expired`` are surfaced as a typed
        error so paginating callers can react (restart vs abort).
        """
        if r.status_code != 400:
            return
        try:
            code, message, _ = parse_error_envelope(r.json())
        except ValueError:
            return
        if code in CURSOR_ERROR_CODES:
            raise CursorError(code, message)

    async def search_all(
        self,
        q: str | None = None,
        *,
        context_type: str | None = None,
        domain: str | None = None,
        agent_id: str | None = None,
        tags: list[str] | None = None,
        derived_from: str | None = None,
        visibility: str | None = None,
        page_size: int = 20,
        max_pages: int = 100,
    ) -> AsyncIterator[SearchHit]:
        """Yield every match across the whole paginated sequence.

        Critically (RFC-ACDP-0005 §2.3) this loop continues while
        ``next_cursor`` is present **even when a page returns zero
        matches** — a storage page whose rows were all post-filtered
        (visibility/tenant) still advances the cursor. Terminating on an
        empty page would silently drop later results.

        ``max_pages`` is a safety bound against a misbehaving registry
        that never stops returning a cursor; reaching it logs nothing
        here but is observable by the caller via the yielded count.
        """
        cursor: str | None = None
        for _ in range(max_pages):
            resp = await self.search(
                q,
                context_type=context_type,
                domain=domain,
                agent_id=agent_id,
                tags=tags,
                derived_from=derived_from,
                visibility=visibility,
                limit=page_size,
                cursor=cursor,
            )
            for hit in resp.matches:
                yield hit
            if not resp.next_cursor:
                return
            cursor = resp.next_cursor

    # ── Lineage ──────────────────────────────────────────────────────────

    async def lineage(self, lineage_id: str) -> list[FullContext]:
        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(
                f"{self._base}/lineages/{lineage_id}", headers=h
            )

        r = await self._retrying(send)
        _raise_for_status(r)
        return [FullContext.model_validate(x) for x in r.json()]

    async def current(self, lineage_id: str) -> FullContext:
        """``GET /lineages/{id}/current`` — the newest non-superseded,
        non-retracted version (RFC-ACDP-0013 §8.3: a retracted head falls
        back to the prior eligible version, or 404s when none remains).

        On a head-receipts-profile registry (RFC-ACDP-0011) the response
        carries ``lineage_head_receipt`` — surfaced on
        :class:`FullContext` as a verbatim dict for
        ``AcdpVerifier.verify_lineage_head_receipt``.
        """

        async def send(h: dict[str, str]) -> httpx.Response:
            return await self._http.get(
                f"{self._base}/lineages/{lineage_id}/current", headers=h
            )

        r = await self._retrying(send)
        _raise_for_status(r)
        return FullContext.model_validate(r.json())

    # ── Cross-registry routing ───────────────────────────────────────────

    @staticmethod
    def _authority_of(ctx_id: str) -> str:
        return ctx_id.removeprefix("acdp://").split("/", 1)[0]

    async def resolve(
        self,
        ctx_id: str,
        authority_map: dict[str, "AcdpClient"],
    ) -> FullContext:
        """Retrieve a context, routing to the registry that owns it.

        Falls back to this client when the authority is unknown (the
        registry's cross-registry resolver will forward in that case).
        """
        authority = self._authority_of(ctx_id)
        client = authority_map.get(authority, self)
        return await client.retrieve(ctx_id)

    # ── Health ───────────────────────────────────────────────────────────

    async def healthz(self) -> bool:
        try:
            r = await self._http.get(f"{self._base}/healthz", timeout=5.0)
            return r.is_success
        except httpx.HTTPError:
            return False

    # ── Data-ref fetch (consumer SSRF guard) ──────────────────────────────

    async def fetch_data_ref(
        self,
        data_ref: dict,
        *,
        policy: "SsrfPolicy | None" = None,
    ) -> bytes:
        """Follow a ``data_refs[].location`` under the consumer SSRF guard.

        Delegates to :mod:`acdp_client.safe_http`: the target host is
        resolved and screened against private/loopback/IMDS ranges
        (mixed-answer rejection), redirects must stay same-authority, and
        the response size is capped. When the entry carries a
        ``content_hash`` the bytes are verified (RFC-ACDP-0008 §4.9).

        This guard is necessary because the playground's ``httpx`` client
        does not go through the Rust SDK's ``RegistryClient`` (where the
        equivalent enforcement lives).
        """
        from acdp_client.safe_http import fetch_data_ref as _fetch

        return await _fetch(data_ref, policy=policy)
