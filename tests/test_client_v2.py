"""Tests for AcdpClient V2 behaviour: cursor pagination + tenant header."""

from __future__ import annotations

import httpx
import pytest

from acdp_client import AcdpClient, CursorError


def _client(handler, **kwargs) -> AcdpClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://reg.test")
    return AcdpClient("http://reg.test", http=http, **kwargs)


# ── cursor pagination ────────────────────────────────────────────────────


async def test_search_all_continues_through_empty_filtered_page():
    """RFC-ACDP-0005 §2.3: a zero-match page with a cursor MUST NOT stop
    pagination — later pages may still hold visible results."""
    # Page plan keyed by inbound cursor:
    #   (none) -> 1 hit  + cursor c1
    #   c1     -> 0 hits + cursor c2   (fully post-filtered storage page)
    #   c2     -> 1 hit  + no cursor   (end)
    pages = {
        None: {"matches": [{"ctx_id": "a"}], "next_cursor": "c1"},
        "c1": {"matches": [], "next_cursor": "c2"},
        "c2": {"matches": [{"ctx_id": "b"}], "next_cursor": None},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor")
        return httpx.Response(200, json=pages[cursor])

    client = _client(handler)
    seen = [hit.ctx_id async for hit in client.search_all("q", page_size=1)]
    assert seen == ["a", "b"]  # the empty middle page did not terminate the loop


async def test_search_all_stops_when_cursor_absent():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"matches": [{"ctx_id": "only"}]})

    client = _client(handler)
    seen = [hit.ctx_id async for hit in client.search_all("q")]
    assert seen == ["only"]


async def test_search_all_respects_max_pages():
    """A registry that never drops the cursor is bounded by max_pages."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"matches": [{"ctx_id": "x"}], "next_cursor": "loop"})

    client = _client(handler)
    seen = [hit async for hit in client.search_all("q", max_pages=3)]
    assert len(seen) == 3


async def test_invalid_cursor_raises_cursor_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"code": "invalid_cursor", "message": "bad"}})

    client = _client(handler)
    with pytest.raises(CursorError) as ei:
        await client.search("q", cursor="garbage")
    assert ei.value.code == "invalid_cursor"


async def test_cursor_expired_raises_cursor_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"code": "cursor_expired", "message": "stale"}})

    client = _client(handler)
    with pytest.raises(CursorError) as ei:
        await client.search("q", cursor="old")
    assert ei.value.code == "cursor_expired"


async def test_other_400_is_not_cursor_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"code": "bad_request"}})

    client = _client(handler)
    from acdp_client import AcdpHTTPError

    with pytest.raises(AcdpHTTPError):
        await client.search("q")


# ── tenant header policy ─────────────────────────────────────────────────


def _captured_header(captured: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        captured["x-tenant-id"] = request.headers.get("x-tenant-id")
        captured["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"matches": []})

    return handler


async def test_tenant_header_fallback_unauthenticated_sends():
    cap: dict = {}
    client = _client(_captured_header(cap), tenant_id="tenant-a")  # no producer
    await client.search("q")
    assert cap["x-tenant-id"] == "tenant-a"


async def test_tenant_header_fallback_authenticated_suppressed():
    cap: dict = {}
    client = _client(_captured_header(cap), tenant_id="tenant-a", bearer_token="static-token")
    await client.search("q")
    # Authenticated → fallback suppresses the header (claim is authoritative).
    assert cap["x-tenant-id"] is None
    assert cap["authorization"] == "Bearer static-token"


async def test_tenant_header_always_sends_even_authenticated():
    cap: dict = {}
    client = _client(
        _captured_header(cap),
        tenant_id="tenant-b",
        bearer_token="static-token",
        tenant_header_mode="always",
    )
    await client.search("q")
    assert cap["x-tenant-id"] == "tenant-b"  # conflict-test mode


async def test_tenant_header_never_mode():
    cap: dict = {}
    client = _client(_captured_header(cap), tenant_id="tenant-a", tenant_header_mode="never")
    await client.search("q")
    assert cap["x-tenant-id"] is None
