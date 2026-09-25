"""Tests for the round-2 scenarios S16 (SSRF guard) and S17 (supersession authz)."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import patch
from urllib.parse import unquote

import httpx

from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id
from playground.config import get_settings
from playground.scenarios import get_scenario, list_scenarios
from playground.scenarios.models import RunSpec


def test_round2_scenarios_registered():
    ids = {s.id for s in list_scenarios()}
    assert {"s16_dataref_ssrf", "s17_supersession_authz"} <= ids


async def test_s16_blocks_all_ssrf_vectors():
    scenario = get_scenario("s16_dataref_ssrf")
    q: asyncio.Queue = asyncio.Queue()
    res = await scenario.run(RunSpec(run_id="r-16", scenario_id="s16_dataref_ssrf"), q)
    assert res.status == "complete"
    guard = res.summary["ssrf_guard"]
    assert guard["imds"].startswith("blocked")
    assert guard["mixed_answer"].startswith("blocked")
    assert guard["cross_port_redirect"] == "refused"
    assert guard["http_scheme"].startswith("blocked")
    assert guard["public_screen"] == "passed"


async def test_s17_degrades_gracefully_without_registry(monkeypatch):
    # Point the registry at an unreachable port so the publish fails fast and
    # the scenario takes its degrade-gracefully path.
    monkeypatch.setenv("REGISTRY_A_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("LLM_PROVIDER", "mock")  # no langchain_openai in CI
    get_settings.cache_clear()
    try:
        scenario = get_scenario("s17_supersession_authz")
        q: asyncio.Queue = asyncio.Queue()
        res = await scenario.run(RunSpec(run_id="r-17", scenario_id="s17_supersession_authz"), q)
        # Degrades to a clean complete (no registry to exercise the live path).
        assert res.status == "complete"
        assert res.summary.get("degraded") is True
        assert res.error is None
    finally:
        get_settings.cache_clear()


async def test_s17_transport_failure_after_owner_publish_is_not_scored_as_blocked(monkeypatch):
    """A registry that dies *between* the owner's publish and the attacker's
    supersede attempt must degrade, not report the ownership check as having
    fired.

    Regression test for a bug where the attacker-publish arm caught bare
    ``Exception`` and set ``attacker_blocked = True`` for *any* failure,
    including a transport-level ``httpx.ConnectError`` — misreporting "the
    registry is unreachable" as "the authorization check rejected the
    attacker". Only a recognized rejection (``SupersededError``, or a
    401/403 ``AcdpHTTPError``) may set ``attacker_blocked``.
    """
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setenv("CONTROL_PLANE_URL", "")
    get_settings.cache_clear()

    published: dict[str, dict] = {}
    calls = {"post": 0}
    authority = get_settings().registry_a_authority

    def envelope(ctx_id: str) -> dict:
        return {
            "body": published[ctx_id],
            "registry_state": {"status": "active"},
            "registry_receipt": None,
        }

    async def fake_post(self, url, content=None, headers=None, **kw):
        calls["post"] += 1
        req_obj = httpx.Request("POST", url)
        if calls["post"] == 1:
            # The owner's v1 publish succeeds.
            req = json.loads(content)
            ctx_id = synthetic_ctx_id(authority, "s17-transport-failure:owner")
            lineage_id = req.get("lineage_id") or synthetic_lineage_id(
                "s17-transport-failure:owner"
            )
            created_at = datetime.now(UTC).isoformat()
            body = {
                **req,
                "ctx_id": ctx_id,
                "lineage_id": lineage_id,
                "version": 1,
                "created_at": created_at,
                "origin_registry": authority,
            }
            body.setdefault("type", body.get("context_type", "data_snapshot"))
            published[ctx_id] = body
            return httpx.Response(
                201,
                json={
                    "ctx_id": ctx_id,
                    "lineage_id": lineage_id,
                    "version": 1,
                    "created_at": created_at,
                    "status": "active",
                },
                request=req_obj,
            )
        # The attacker's supersede attempt hits a dead registry.
        raise httpx.ConnectError("connection refused", request=req_obj)

    async def fake_get(self, url, *a, **kw):
        req_obj = httpx.Request("GET", url)
        path = httpx.URL(url).path
        if path.endswith(("/healthz", "/readyz")):
            return httpx.Response(200, json={"ok": True}, request=req_obj)
        ctx_id = unquote(path.split("/contexts/", 1)[1])
        return httpx.Response(200, json=envelope(ctx_id), request=req_obj)

    try:
        with (
            patch.object(httpx.AsyncClient, "post", fake_post),
            patch.object(httpx.AsyncClient, "get", fake_get),
        ):
            scenario = get_scenario("s17_supersession_authz")
            q: asyncio.Queue = asyncio.Queue()
            res = await scenario.run(
                RunSpec(run_id="r-17-transport-down", scenario_id="s17_supersession_authz"), q
            )
        assert res.status == "complete"
        assert res.summary.get("degraded") is True
        assert res.summary.get("attacker_blocked") is not True
        assert res.error is None
    finally:
        get_settings.cache_clear()
