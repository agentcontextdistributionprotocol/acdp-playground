"""Backend access gate and client-IP resolution.

Every route except the two in :data:`EXEMPT_PATHS` sits behind a shared
``x-api-key``. The gate is ASGI middleware rather than a per-router
dependency so it is fail-closed: FastAPI's own ``/docs``, ``/redoc`` and
``/openapi.json``, the SSE streams, unknown paths, and any route added later
are covered without anyone remembering to attach a dependency.

``/healthz`` stays open for the platform health check, and ``/webhooks/acdp``
authenticates each delivery with its own HMAC signature.

Enforcement is staged by ``PLAYGROUND_REQUIRE_API_KEY``:

- **false** (default): requests without a valid key still pass, so callers
  can start sending the key before it is required. A key that is presented
  but wrong is logged and treated as absent.
- **true**: a missing or wrong key gets ``401`` before any route or limiter
  runs. ``Settings`` refuses to load when this is on and no key is set.

The middleware also resolves the caller's IP for the per-IP limits and
stores both facts in ``scope["state"]`` (read as ``request.state``):

- ``api_key_valid``: the request carried the configured key.
- ``client_ip``: the ``X-ACDP-Client-IP`` header when the key is valid and
  the value parses as an IP address, otherwise the socket peer. Without the
  key the header is ignored, so nobody can pick their own rate-limit bucket.
- ``per_ip_limits``: whether per-IP limits apply to this request. They apply
  to keyed requests always, and to keyless requests only once enforcement is
  on. Until then a keyless request's socket peer is the platform edge proxy,
  shared by every user, so a per-IP bucket for it would throttle everyone
  together.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from playground.config import get_settings

log = logging.getLogger(__name__)

API_KEY_HEADER = "x-api-key"
CLIENT_IP_HEADER = "x-acdp-client-ip"
EXEMPT_PATHS = frozenset({"/healthz", "/webhooks/acdp"})


def _header(scope: Scope, name: str) -> str | None:
    raw = name.encode("latin-1")
    for key, value in scope.get("headers") or ():
        if key.lower() == raw:
            return value.decode("latin-1")
    return None


def key_matches(presented: str | None, configured: str) -> bool:
    """Constant-time comparison; an unset configured key never matches."""
    if not configured or presented is None:
        return False
    return hmac.compare_digest(presented.encode(), configured.encode())


def _parse_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    # One bucket per subscriber: an IPv4-mapped address is its IPv4 address,
    # and an IPv6 address counts as its /64 (one end site's allocation), so a
    # user can't rotate through their prefix to get fresh limits.
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def resolve_client_ip(scope: Scope, *, trusted: bool) -> str:
    """The caller's IP: the forwarded header if ``trusted``, else the socket peer."""
    if trusted:
        forwarded = _parse_ip(_header(scope, CLIENT_IP_HEADER))
        if forwarded is not None:
            return forwarded
    client = scope.get("client")
    return client[0] if client else "unknown"


class ApiKeyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        presented = _header(scope, API_KEY_HEADER)
        valid = key_matches(presented, settings.playground_api_key)
        enforced = settings.playground_require_api_key

        state: dict[str, Any] = scope.setdefault("state", {})
        state["api_key_valid"] = valid
        state["client_ip"] = resolve_client_ip(scope, trusted=valid)
        state["per_ip_limits"] = valid or enforced

        if scope["path"] in EXEMPT_PATHS or valid:
            await self.app(scope, receive, send)
            return

        if presented is not None:
            log.warning("rejected x-api-key on %s %s", scope.get("method", ""), scope["path"])
        if not enforced:
            await self.app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"detail": "missing or invalid x-api-key"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", b'ApiKey header="x-api-key"'),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
