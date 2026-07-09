"""Tests for the round-2 scenarios S16 (SSRF guard) and S17 (supersession authz)."""

from __future__ import annotations

import asyncio

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
