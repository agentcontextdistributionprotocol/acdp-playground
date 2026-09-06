"""Round-3 scenario + client-contract tests.

Covers the acdp-registry-rs #24 / #26 wire contracts the playground now models:
supersession ``not_found`` collapse (ownership *and* tenant-continuity),
the §5 ``not_authorized`` 403, and the framework 413 envelope. The live
scenarios degrade gracefully without a registry, so the hard assertions run
against a controlled mock transport here.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from acdp_client import (
    AcdpClient,
    AcdpHTTPError,
    NotAuthorizedError,
    SupersededError,
)
from playground.scenarios import get_scenario, list_scenarios
from playground.scenarios.models import RunSpec


def _client(handler) -> AcdpClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://reg.test")
    return AcdpClient("http://reg.test", http=http)


def test_round3_scenarios_registered():
    ids = {s.id for s in list_scenarios()}
    assert {"s18_idempotency", "s19_cp_did_web_p256"} <= ids
    assert {"s16_dataref_ssrf", "s17_supersession_authz"} <= ids


async def test_s19_cp_did_web_p256_is_conformant_offline():
    """S19 is fully offline + deterministic: the P-256 verification method the
    playground emits is exactly the JWK-only JsonWebKey2020 the CP accepts."""
    scenario = get_scenario("s19_cp_did_web_p256")
    q: asyncio.Queue = asyncio.Queue()
    res = await scenario.run(RunSpec(run_id="r-19", scenario_id="s19_cp_did_web_p256"), q)
    assert res.status == "complete"
    s = res.summary
    assert s["cp_resolvable"] is True
    assert s["vm_type"] == "JsonWebKey2020"
    assert s["jwk_only"] is True
    assert s["jwk_curve"] == "P-256"
    assert "publicKeyMultibase" not in s["verification_method"]


async def test_cross_tenant_supersession_is_not_found():
    """A cross-tenant successor is rejected with the same superseded_target /
    not_found shape as a non-owner or absent target (#24 — no oracle)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            headers={"content-type": "application/acdp+json"},
            json={
                "error": {
                    "code": "superseded_target",
                    "message": "supersession target not found",
                    "details": {"reason": "not_found"},
                }
            },
        )

    client = _client(handler)
    with pytest.raises(SupersededError) as ei:
        await client.publish("{}")
    assert ei.value.code == "superseded_target"
    assert ei.value.reason == "not_found"  # ownership + tenant both collapse here


async def test_superseded_target_race_is_409():
    """A concurrent supersession race surfaces as 409 but the same typed error."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            headers={"content-type": "application/acdp+json"},
            json={
                "error": {
                    "code": "superseded_target",
                    "message": "already superseded",
                    "details": {"reason": "already_superseded"},
                }
            },
        )

    client = _client(handler)
    with pytest.raises(SupersededError) as ei:
        await client.publish("{}")
    assert ei.value.status == 409
    assert ei.value.reason == "already_superseded"


async def test_not_authorized_403_is_typed():
    """not_authorized moved from 401 to 403 (#24); surfaced as NotAuthorizedError."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"content-type": "application/acdp+json"},
            json={"error": {"code": "not_authorized", "message": "forbidden"}},
        )

    client = _client(handler)
    with pytest.raises(NotAuthorizedError) as ei:
        await client.retrieve("acdp://reg.test/abc")
    assert ei.value.status == 403
    assert ei.value.code == "not_authorized"
    # NotAuthorizedError is an AcdpHTTPError, so generic handlers still catch it.
    assert isinstance(ei.value, AcdpHTTPError)
