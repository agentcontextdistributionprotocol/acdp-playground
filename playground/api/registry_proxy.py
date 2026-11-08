"""GET /registries/{a|b}/... — allow-listed, read-only passthrough to the registries.

Lets the console reach registry-a/registry-b through the (key-gated)
playground over the private network, so the registries can drop their
public domains. It is not a generic reverse proxy: only the read paths
the console issues (its ``REGISTRY_ROUTES`` allowlist) plus the raw context
retrieval are forwarded. Everything else is a 404 before any upstream
request is made.

``/contexts/{ctx_id}`` returns the registry's response bytes unchanged
(same ``Content-Type`` and ``ETag``), so anyone can still re-hash a body and
verify its signature and receipt end to end without reaching the registry
directly. A ctx_id contains ``/`` (scheme, authority, UUID), so callers send it
percent-encoded as ONE path segment; routing therefore works on the raw
(still-encoded) path, never the decoded one.

The upstream base URL comes only from settings (``REGISTRY_A_URL`` /
``REGISTRY_B_URL``); no route takes a host, so this cannot be pointed at an
arbitrary target. Redirects are not followed. The query string is forwarded
(``/contexts/search`` needs it); request headers are not, apart from
``Accept`` and ``If-None-Match``, so the caller's ``x-api-key`` never
reaches a registry.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal
from urllib.parse import quote, unquote

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from acdp_client.identifiers import is_conformant_ctx_id
from playground.config import get_settings

router = APIRouter(prefix="/registries", tags=["registries"])


# Each route is a tuple of segments, matched against the DECODED segments of
# the raw path (so ``%2F`` inside an id stays inside its one segment). A
# literal must match exactly; a predicate validates a free id segment.
def _lineage_id(seg: str) -> bool:
    return "/" not in seg  # (and not ""/"."/"..", rejected for every segment)


ALLOWED_ROUTES: tuple[tuple[str | Callable[[str], bool], ...], ...] = (
    ("healthz",),
    ("contexts", "search"),
    ("contexts", is_conformant_ctx_id),
    ("lineages", _lineage_id),
    ("lineages", _lineage_id, "current"),
    (".well-known", "acdp.json"),
    (".well-known", "jwks.json"),
    (".well-known", "did.json"),
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


def allowed_segments(raw_rest: str) -> list[str] | None:
    """Decoded segments of an allow-listed raw path remainder, else None."""
    segments = [unquote(seg) for seg in raw_rest.split("/")]
    if any(seg in ("", ".", "..") for seg in segments):
        return None
    for route in ALLOWED_ROUTES:
        if len(route) == len(segments) and all(
            want == got if isinstance(want, str) else want(got)
            for want, got in zip(route, segments, strict=True)
        ):
            return segments
    return None


def is_allowed(raw_rest: str) -> bool:
    return allowed_segments(raw_rest) is not None


def _raw_rest(request: Request, registry: str, path: str) -> str:
    raw = request.scope.get("raw_path")
    if not raw:
        return quote(path, safe="/:@")
    prefix = f"/registries/{registry}/".encode()
    return raw.split(b"?", 1)[0].removeprefix(prefix).decode("latin-1")


@router.get("/{registry}/{path:path}")
async def proxy(registry: Literal["a", "b"], path: str, request: Request) -> Response:
    segments = allowed_segments(_raw_rest(request, registry, path))
    if segments is None:
        raise HTTPException(404, f"not an allow-listed registry path: /{path}")
    s = get_settings()
    base = s.registry_a_url if registry == "a" else s.registry_b_url
    # Re-encode every decoded segment fully (as AcdpClient does for ctx ids),
    # so an id can't smuggle '/', '?' or '#' into the upstream URL.
    url = (
        base.rstrip("/")
        + "/"
        + "/".join(quote(seg, safe="" if "/" in seg else ":@") for seg in segments)
    )
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
