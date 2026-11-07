"""GET /registries/{a|b}/... — allow-listed, read-only passthrough to the registries.

Lets the console reach registry-a/registry-b through the (key-gated)
playground over the private network, so the registries can drop their
public domains. It is not a generic reverse proxy: only the exact read
paths the console issues are forwarded, mirroring the console's own
``REGISTRY_ROUTES`` allowlist. Everything else is a 404 before any upstream
request is made.

The upstream base URL comes only from settings (``REGISTRY_A_URL`` /
``REGISTRY_B_URL``); no route takes a host, so this cannot be pointed at an
arbitrary target. Redirects are not followed. The query string is forwarded
(``/contexts/search`` needs it); request headers are not, apart from
``Accept`` and ``If-None-Match``, so the caller's ``x-api-key`` never
reaches a registry.
"""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from playground.config import get_settings

router = APIRouter(prefix="/registries", tags=["registries"])

ALLOWED_PATHS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"^healthz$",
        r"^contexts/search$",
        r"^lineages/[^/]+$",
        r"^lineages/[^/]+/current$",
        r"^\.well-known/acdp\.json$",
        r"^\.well-known/jwks\.json$",
        r"^\.well-known/did\.json$",
    )
)
_FORWARD_REQUEST_HEADERS = ("accept", "if-none-match")
_FORWARD_RESPONSE_HEADERS = (
    "content-type",
    "cache-control",
    "etag",
    "last-modified",
    "retry-after",
    "vary",
)

_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            timeout=get_settings().registry_proxy_timeout_seconds, follow_redirects=False
        )
    return _client


async def aclose() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def is_allowed(path: str) -> bool:
    if any(seg in ("", ".", "..") for seg in path.split("/")):
        return False
    return any(p.match(path) for p in ALLOWED_PATHS)


@router.get("/{registry}/{path:path}")
async def proxy(registry: Literal["a", "b"], path: str, request: Request) -> Response:
    if not is_allowed(path):
        raise HTTPException(404, f"not an allow-listed registry path: /{path}")
    s = get_settings()
    base = s.registry_a_url if registry == "a" else s.registry_b_url
    # Path params arrive percent-decoded; re-encode each segment so an id
    # can't smuggle a '?' or '#' into the upstream URL.
    url = base.rstrip("/") + "/" + "/".join(quote(seg, safe=":@") for seg in path.split("/"))
    if request.url.query:
        url += "?" + request.url.query
    headers = {h: v for h in _FORWARD_REQUEST_HEADERS if (v := request.headers.get(h))}
    try:
        upstream = await _get_client().get(url, headers=headers)
    except httpx.HTTPError as e:
        raise HTTPException(
            502, {"code": "registry_unreachable", "registry": registry, "detail": type(e).__name__}
        ) from None
    out_headers = {
        h: v for h in _FORWARD_RESPONSE_HEADERS if (v := upstream.headers.get(h)) is not None
    }
    return Response(content=upstream.content, status_code=upstream.status_code, headers=out_headers)
