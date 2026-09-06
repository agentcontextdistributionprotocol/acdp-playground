"""Optional bridge to the ACDP control plane.

When ``CONTROL_PLANE_URL`` is empty (the default), the forwarding
methods are no-ops. When it's set, run-lifecycle notifications and
forwarded registry webhooks are sent to the control plane with an
HMAC-SHA256 signature in ``X-ACDP-Signature: sha256=<hex>``.

Beyond fire-and-forget forwarding, this client also drives the CP's
operator surface when an admin token is configured:

* ``introspect`` — RFC 7662 token introspection (``POST /auth/introspect``)
* ``revocations`` — cross-issuer revocation feed (``GET /auth/revocations``)
* ``events`` — keyset-paginated cross-run event history (``GET /events``)
* ``declare_capability`` — self-declare an agent capability (``POST /capabilities``)
* ``reload_pinned_keys`` — hot key-rotation (``POST /admin/pinned-keys/reload``)

Forwarded webhooks preserve the registry's ``X-ACDP-Event``,
``X-ACDP-Event-Id`` (retry-stable dedup key) and carry an
``X-Tenant-Id`` so the multi-tenant CP attributes the event correctly.
The tenant is a routing signal carried in the header — never in the
signed body (RFC-ACDP-0008 §6.4).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from acdp_client.identifiers import reject_reserved_tenant
from acdp_client.models import parse_error_envelope
from playground.config import Settings
from playground.retry_after import parse_retry_after

log = logging.getLogger(__name__)

# Transient upstream statuses worth one cooperative retry.
_RETRYABLE = {429, 502, 503, 504}
_MAX_RETRY_DELAY = 30.0  # cap a cooperative Retry-After wait

# The control plane's RunCompleteDto accepts only completed|failed|cancelled.
# The playground's RunResult uses "complete" for the success terminal state, so
# normalize it to the CP vocabulary — otherwise /runs/{id}/complete 400s and the
# run is stuck "running" in the dashboard.
_CP_TERMINAL_STATUS = {"complete": "completed"}


def _sign(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _describe_cp_error(r: httpx.Response) -> str:
    """Summarise a non-2xx control-plane response for an operator log.

    The CP now emits the RFC-ACDP-0007 ACDP error envelope
    (``{"error":{"code","message","details"}}`` as ``application/acdp+json``,
    CP #49) on its error and revocation-feed responses. We parse it so the log
    carries the machine ``code``/``reason`` rather than just the status. This
    is observability only — the bridge keeps its fire-and-forget / return-None
    contract regardless.
    """
    parts = [f"status={r.status_code}"]
    try:
        code, message, details = parse_error_envelope(r.json())
    except ValueError:
        return parts[0]
    if code:
        parts.append(f"code={code}")
    if isinstance(details, dict) and isinstance(details.get("reason"), str):
        parts.append(f"reason={details['reason']}")
    if message:
        parts.append(f"message={message[:120]}")
    return " ".join(parts)


class ControlPlaneClient:
    """No-op when URL unset; otherwise fires-and-forgets HTTP calls."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._http: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self._settings.control_plane_url)

    @property
    def _base(self) -> str:
        return self._settings.control_plane_url.rstrip("/")

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            async with self._lock:
                if self._http is None:
                    self._http = httpx.AsyncClient(timeout=10.0)
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ── core POST with HMAC + one cooperative retry ──────────────────────

    async def _post(
        self,
        path: str,
        body: bytes,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if not self.enabled:
            return
        url = self._base + path
        headers = {"Content-Type": "application/json"}
        if self._settings.control_plane_hmac_secret:
            headers["X-ACDP-Signature"] = _sign(self._settings.control_plane_hmac_secret, body)
        if extra_headers:
            headers.update(extra_headers)
        try:
            client = await self._client()
            r = await client.post(url, content=body, headers=headers)
            if r.status_code in _RETRYABLE:
                delay = parse_retry_after(r.headers.get("retry-after"), now=time.time())
                if delay is not None:
                    await asyncio.sleep(min(delay, _MAX_RETRY_DELAY))
                    r = await client.post(url, content=body, headers=headers)
            if not r.is_success:
                log.warning("control-plane %s -> %s", path, _describe_cp_error(r))
        except httpx.HTTPError as e:
            # Never let control-plane outages break a run.
            log.warning("control-plane %s failed: %s", path, e)

    # ── lifecycle events ─────────────────────────────────────────────────

    async def notify_run_started(
        self,
        run_id: str,
        scenario_id: str,
        inputs: dict[str, Any],
        *,
        tenant_id: str | None = None,
    ) -> None:
        payload = {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "started_at": datetime.now(UTC).isoformat(),
            "inputs": inputs,
        }
        await self._post(
            "/runs/started",
            json.dumps(payload).encode("utf-8"),
            extra_headers=_tenant_header(tenant_id),
        )

    async def notify_run_complete(
        self,
        run_id: str,
        status: str,
        result: dict[str, Any] | None,
        *,
        tenant_id: str | None = None,
    ) -> None:
        payload = {
            "run_id": run_id,
            "status": _CP_TERMINAL_STATUS.get(status, status),
            "completed_at": datetime.now(UTC).isoformat(),
            "result": result,
        }
        await self._post(
            f"/runs/{run_id}/complete",
            json.dumps(payload).encode("utf-8"),
            extra_headers=_tenant_header(tenant_id),
        )

    # ── webhook forwarding ──────────────────────────────────────────────

    async def forward_webhook(
        self,
        raw_body: bytes,
        headers: dict[str, str],
        *,
        tenant_id: str | None = None,
    ) -> None:
        """Forward a registry webhook verbatim to the control plane.

        Re-signs with the control plane's secret if configured (the
        registry's signature wouldn't validate there). Preserves the
        event type, the retry-stable dedup id, and the run correlation
        id, and stamps an ``X-Tenant-Id`` for tenant attribution.
        """
        lower = {k.lower(): v for k, v in headers.items()}
        extra: dict[str, str] = {}
        if event := lower.get("x-acdp-event"):
            extra["X-ACDP-Event"] = event
        if event_id := lower.get("x-acdp-event-id"):
            extra["X-ACDP-Event-Id"] = event_id
        if run_id := lower.get("x-run-id"):
            extra["X-Run-Id"] = run_id
        # An explicit tenant arg wins; else honour an inbound header. The
        # reserved `default` sentinel may never be asserted — the CP AuthGuard
        # (#50) 403s it, so reject it here with a clearer local error.
        tenant = tenant_id or lower.get("x-tenant-id")
        if tenant:
            reject_reserved_tenant(tenant)
            extra["X-Tenant-Id"] = tenant
        await self._post("/ingest/acdp", raw_body, extra_headers=extra)

    # ── admin / operator surface (requires control_plane_admin_token) ────

    def _admin_headers(self) -> dict[str, str] | None:
        token = self._settings.control_plane_admin_token
        if not token:
            return None
        return {"Authorization": f"Bearer {token}"}

    async def introspect(self, token: str) -> dict[str, Any] | None:
        """RFC 7662 introspection — returns the decoded claims or None.

        Requires an admin token. Returns ``{"active": false}`` shape when
        the CP reports the token inactive/revoked.
        """
        admin = self._admin_headers()
        if not self.enabled or admin is None:
            return None
        url = self._base + "/auth/introspect"
        headers = {**admin, "Content-Type": "application/json"}
        try:
            client = await self._client()
            r = await client.post(url, json={"token": token}, headers=headers)
        except httpx.HTTPError as e:
            log.warning("control-plane introspect failed: %s", e)
            return None
        if not r.is_success:
            log.warning("control-plane introspect -> %s", _describe_cp_error(r))
            return None
        return r.json()

    async def revocations(self, *, since_ms: int = 0, limit: int = 200) -> dict[str, Any] | None:
        """Read the cross-issuer revocation feed (admin-only).

        Returns ``{"entries": [...], "next_cursor": <int|null>}`` or None
        when disabled/unauthorized.
        """
        admin = self._admin_headers()
        if not self.enabled or admin is None:
            return None
        url = self._base + "/auth/revocations"
        try:
            client = await self._client()
            r = await client.get(url, params={"since": since_ms, "limit": limit}, headers=admin)
        except httpx.HTTPError as e:
            log.warning("control-plane revocations failed: %s", e)
            return None
        if not r.is_success:
            log.warning("control-plane revocations -> %s", _describe_cp_error(r))
            return None
        return r.json()

    async def events(
        self,
        *,
        before_ts: str | None = None,
        limit: int = 500,
        run_id: str | None = None,
        event_type: str | None = None,
    ) -> dict[str, Any] | None:
        """Read the CP cross-run event history (``GET /events``, admin-gated).

        Returns the keyset-paginated page ``{"data": [...], "limit": <int>,
        "nextCursor": <ts|null>}``. CP #51 caps ``limit`` server-side, so the
        echoed ``limit`` may be lower than requested. Walk to older pages by
        passing the previous page's ``nextCursor`` back as ``before_ts``.
        Returns ``None`` when the bridge is disabled or unauthorized.
        """
        admin = self._admin_headers()
        if not self.enabled or admin is None:
            return None
        url = self._base + "/events"
        params: dict[str, Any] = {"limit": limit}
        if before_ts is not None:
            params["beforeTs"] = before_ts
        if run_id is not None:
            params["runId"] = run_id
        if event_type is not None:
            params["eventType"] = event_type
        try:
            client = await self._client()
            r = await client.get(url, params=params, headers=admin)
        except httpx.HTTPError as e:
            log.warning("control-plane events failed: %s", e)
            return None
        if not r.is_success:
            log.warning("control-plane events -> %s", _describe_cp_error(r))
            return None
        return r.json()

    async def declare_capability(
        self,
        *,
        agent_did: str,
        capability_uri: str,
        declared_at: str,
        key_id: str,
        algorithm: str,
        signature: str,
        tenant_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Self-declare an agent capability (``POST /capabilities``, auth-gated).

        ``signature`` must be base64 over
        ``acdp-cap:v1:<agent_did>:<capability_uri>:<declared_at>`` and verify
        against the agent's pinned key. CP #51 lets ``algorithm`` be either
        ``ed25519`` or ``ecdsa-p256`` — the DTO previously rejected P-256 at the
        validation boundary. Returns the declaration record on success, else
        ``None``.
        """
        admin = self._admin_headers()
        if not self.enabled or admin is None:
            return None
        url = self._base + "/capabilities"
        body = {
            "agent_did": agent_did,
            "capability_uri": capability_uri,
            "declared_at": declared_at,
            "key_id": key_id,
            "algorithm": algorithm,
            "signature": signature,
        }
        headers = {**admin, "Content-Type": "application/json"}
        if extra := _tenant_header(tenant_id):
            headers.update(extra)
        try:
            client = await self._client()
            r = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as e:
            log.warning("control-plane capability declare failed: %s", e)
            return None
        if not r.is_success:
            log.warning("control-plane capability declare -> %s", _describe_cp_error(r))
            return None
        return r.json()

    async def domain_packs(self) -> dict[str, Any] | None:
        """List the control plane's active runtime domain packs.

        ``GET /domain-packs`` (CP ``6d4255b``) returns the packs that gate
        custom ``context_type`` values on ingest. Public — no admin token
        required. Returns ``{"packs": [...]}`` or ``None`` when the bridge
        is disabled or the CP is unreachable.
        """
        if not self.enabled:
            return None
        url = self._base + "/domain-packs"
        try:
            client = await self._client()
            r = await client.get(url)
        except httpx.HTTPError as e:
            log.warning("control-plane domain-packs failed: %s", e)
            return None
        if not r.is_success:
            log.warning("control-plane domain-packs -> %s", _describe_cp_error(r))
            return None
        return r.json()

    async def reload_pinned_keys(self) -> dict[str, Any] | None:
        """Trigger a hot reload of the CP pinned-key directory (admin)."""
        admin = self._admin_headers()
        if not self.enabled or admin is None:
            return None
        url = self._base + "/admin/pinned-keys/reload"
        try:
            client = await self._client()
            r = await client.post(url, headers=admin)
        except httpx.HTTPError as e:
            log.warning("control-plane pinned-key reload failed: %s", e)
            return None
        if not r.is_success:
            log.warning("control-plane pinned-key reload -> %s", _describe_cp_error(r))
            return None
        return r.json()


def _tenant_header(tenant_id: str | None) -> dict[str, str] | None:
    if not tenant_id:
        return None
    # The CP rejects an explicitly-asserted `default` tenant (#50); fail fast.
    reject_reserved_tenant(tenant_id)
    return {"X-Tenant-Id": tenant_id}


_singleton: ControlPlaneClient | None = None


def get_control_plane(settings: Settings) -> ControlPlaneClient:
    global _singleton
    if _singleton is None:
        _singleton = ControlPlaneClient(settings)
    return _singleton
