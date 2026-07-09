"""Reserved-tenant (`default`) rejection — client guard + server contract.

The reserved sentinel may never be *asserted* as a tenant. Both siblings
reject it server-side (registry ``c988ea4`` → 400 ``schema_violation``;
control plane ``#50`` → 403 ``not_authorized``); the playground mirrors the
rule client-side so a caller fails fast locally. These tests cover the
standalone guard, the :class:`AcdpClient` / control-plane-bridge wiring, the
S20 offline scenario, and the parsing of both server rejection shapes.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from acdp_client import (
    AcdpClient,
    AcdpHTTPError,
    NotAuthorizedError,
    RESERVED_TENANT,
    is_reserved_tenant,
    reject_reserved_tenant,
)
from playground.control_plane import _tenant_header
from playground.scenarios import get_scenario, list_scenarios
from playground.scenarios.models import RunSpec


# ── standalone guard ────────────────────────────────────────────────────


def test_reserved_constant_is_default():
    assert RESERVED_TENANT == "default"


def test_is_reserved_tenant():
    assert is_reserved_tenant("default") is True
    assert is_reserved_tenant("tenant-a") is False
    assert is_reserved_tenant(None) is False


def test_reject_reserved_tenant_blocks_default():
    with pytest.raises(ValueError, match="reserved tenant sentinel"):
        reject_reserved_tenant("default")


def test_reject_reserved_tenant_allows_none_and_real():
    # Absence of an assertion is legitimate untenanted access.
    reject_reserved_tenant(None)
    reject_reserved_tenant("tenant-a")


# ── wiring: AcdpClient + control-plane bridge ───────────────────────────


def test_client_ctor_rejects_default_tenant():
    with pytest.raises(ValueError, match="reserved tenant sentinel"):
        AcdpClient("http://reg.test", tenant_id="default")


def test_client_ctor_allows_real_and_untenanted():
    AcdpClient("http://reg.test", tenant_id=None)
    AcdpClient("http://reg.test", tenant_id="tenant-a")


def test_cp_bridge_tenant_header_rejects_default():
    with pytest.raises(ValueError, match="reserved tenant sentinel"):
        _tenant_header("default")


def test_cp_bridge_tenant_header_allows_real_and_none():
    assert _tenant_header(None) is None
    assert _tenant_header("tenant-a") == {"X-Tenant-Id": "tenant-a"}


# ── S20 scenario (fully offline) ────────────────────────────────────────


def test_s20_registered():
    assert "s20_reserved_tenant" in {s.id for s in list_scenarios()}


async def test_s20_reserved_tenant_offline_passes():
    scenario = get_scenario("s20_reserved_tenant")
    q: asyncio.Queue = asyncio.Queue()
    res = await scenario.run(RunSpec(run_id="r-20", scenario_id="s20_reserved_tenant"), q)
    assert res.status == "complete"
    guard = res.summary["reserved_tenant_guard"]
    assert guard["guard"] == "blocked"
    assert guard["client_ctor"] == "blocked"
    assert guard["cp_bridge"] == "blocked"
    assert guard["untenanted"] == "allowed"
    assert guard["real_tenant"] == "allowed"


# ── server wire contract (mock transport) ───────────────────────────────


def _client(handler) -> AcdpClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://reg.test")
    return AcdpClient("http://reg.test", http=http)


async def test_registry_reserved_tenant_surfaces_400_schema_violation():
    """A registry rejects an asserted `default` tenant as 400 schema_violation."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            headers={"Content-Type": "application/acdp+json"},
            json={
                "error": {
                    "code": "schema_violation",
                    "reason": "'default' is a reserved tenant sentinel and "
                    "cannot be asserted via X-Tenant-Id or a token claim",
                }
            },
        )

    client = _client(handler)
    try:
        with pytest.raises(AcdpHTTPError) as ei:
            await client.retrieve_raw("ctx-1")
        assert ei.value.status == 400
        assert ei.value.code == "schema_violation"
    finally:
        await client.aclose()


async def test_cp_reserved_tenant_surfaces_403_not_authorized():
    """The control plane rejects an asserted `default` tenant as 403."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"Content-Type": "application/acdp+json"},
            json={
                "error": {
                    "code": "not_authorized",
                    "reason": "'default' is a reserved tenant sentinel and "
                    "cannot be asserted via X-Tenant-Id header",
                }
            },
        )

    client = _client(handler)
    try:
        with pytest.raises(NotAuthorizedError) as ei:
            await client.retrieve_raw("ctx-1")
        assert ei.value.status == 403
        assert ei.value.code == "not_authorized"
    finally:
        await client.aclose()
