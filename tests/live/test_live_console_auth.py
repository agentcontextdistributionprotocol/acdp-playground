"""UI console sign-in against the full stack (#98).

``docker-compose.full.yml`` runs the console as a production Next server, which
fails *closed* (503 on every ``/api/proxy`` and ``/api/stream`` call) when
``ACDP_UI_CONSOLE_PASSWORD`` is unset. The compose file now supplies a default
passphrase; this checks the console actually accepts it and proxies a real
backend call, and that the gate still refuses an unauthenticated or wrong
caller.

The CI live job boots only ``registry-a`` and ``control-plane`` (no console
build), so this is gated behind its own ``ACDP_LIVE_CONSOLE`` flag in addition
to ``ACDP_LIVE_STACK``. Run it after ``make up-full``. An override set only in
the playground ``.env`` reaches compose but not pytest — export it too.
"""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ACDP_LIVE_CONSOLE"),
    reason="needs the ui-console from `make up-full` — set ACDP_LIVE_CONSOLE=1",
)

CONSOLE_URL = os.environ.get("ACDP_UI_CONSOLE_URL", "http://localhost:3000").rstrip("/")
# Same semantics as compose's `${ACDP_UI_CONSOLE_PASSWORD:-playground-console}`:
# unset *or empty* falls back to the default.
PASSPHRASE = os.environ.get("ACDP_UI_CONSOLE_PASSWORD") or "playground-console"

LOGIN = "/api/auth/login"
# A cheap, allow-listed, read-only GET the console forwards to the playground.
PROBE = "/api/proxy/playground/healthz"
# Set by the console's proxy route only on responses re-streamed from upstream,
# so it tells a backend answer apart from the middleware's own 401/503.
PROXY_HEADER = "x-acdp-ui-proxy"

_READY_TIMEOUT_S = 30.0
_READY_INTERVAL_S = 1.0
_UPSTREAM_NOT_READY = frozenset({502, 503, 504})


async def _login(client: httpx.AsyncClient, passphrase: str) -> httpx.Response:
    return await client.post(LOGIN, json={"passphrase": passphrase})


async def _probe_until_ready(client: httpx.AsyncClient) -> httpx.Response:
    """Poll the proxied probe until upstream answers 200.

    ``ui-console`` waits on ``playground`` only with ``service_started``, so the
    first proxied call can race the playground's boot and get a 502/503. Any
    other status (a 401/403 from the console itself) is permanent: return it at
    once rather than burning the whole timeout.
    """
    deadline = asyncio.get_running_loop().time() + _READY_TIMEOUT_S
    while True:
        resp = await client.get(PROBE)
        if resp.status_code not in _UPSTREAM_NOT_READY:
            return resp
        if asyncio.get_running_loop().time() >= deadline:
            return resp
        await asyncio.sleep(_READY_INTERVAL_S)


async def test_default_passphrase_signs_in_and_proxies_a_backend_call():
    async with httpx.AsyncClient(base_url=CONSOLE_URL, timeout=10.0) as client:
        login = await _login(client, PASSPHRASE)
        assert login.status_code == 200, (
            f"login returned {login.status_code}: {login.text} — a 503 means the "
            "console has no ACDP_UI_CONSOLE_PASSWORD (the #98 regression)"
        )
        assert "set-cookie" in login.headers
        assert client.cookies, "login set no session cookie"

        resp = await _probe_until_ready(client)
        assert resp.status_code == 200, (
            f"{PROBE} returned {resp.status_code} after {_READY_TIMEOUT_S:.0f}s: {resp.text}"
        )
        assert resp.headers.get(PROXY_HEADER) == "playground"


async def test_gated_route_without_a_session_is_401_not_503():
    async with httpx.AsyncClient(base_url=CONSOLE_URL, timeout=10.0) as client:
        resp = await client.get(PROBE)
    assert resp.status_code == 401, f"expected 401, got {resp.status_code}: {resp.text}"
    assert resp.json()["error"].startswith("Unauthorized: sign in")
    assert PROXY_HEADER not in resp.headers


async def test_wrong_passphrase_is_rejected_without_a_cookie():
    async with httpx.AsyncClient(base_url=CONSOLE_URL, timeout=10.0) as client:
        resp = await _login(client, PASSPHRASE + "-wrong")
        assert resp.status_code == 401, f"expected 401, got {resp.status_code}: {resp.text}"
        assert "set-cookie" not in resp.headers
        assert not client.cookies
