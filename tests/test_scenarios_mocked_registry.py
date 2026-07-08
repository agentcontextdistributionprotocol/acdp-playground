"""Offline execution of the happy-path scenarios S2–S5, S7, S8 against a
stateful in-process fake registry.

These scenarios previously ran only against the live docker stack, so their
``run()`` bodies had zero offline coverage. Here a minimal fake registry —
patched over ``httpx.AsyncClient.post/get`` like the S1 e2e test — accepts
SDK-signed publish requests, assigns ``ctx_id``/``lineage_id``/``version``,
and serves retrieval + lineage reads, so the full agent flow (publish →
resolve derived_from → derivative publish) executes for real.

The fake models just enough of the registry to satisfy the client's Pydantic
parsing; protocol *semantics* (signature checks, tenancy, supersession rules)
stay the job of the live conformance suite (`make test-live`).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.parse import unquote

import httpx
import pytest

from playground.config import get_settings
from playground.scenarios import get_scenario
from playground.scenarios.models import RunSpec


class FakeRegistry:
    """Stateful stand-in for both registries, keyed by request URL.

    Stores every published body verbatim (plus the registry-assigned
    fields) so later retrieves/lineage reads return what was published.
    """

    def __init__(self, settings):
        self._settings = settings
        self.contexts: dict[str, dict] = {}
        self.lineages: dict[str, list[str]] = {}

    def _authority_for(self, url: str) -> str:
        s = self._settings
        if url.startswith(s.registry_b_url):
            return s.registry_b_authority
        return s.registry_a_authority

    # ── handlers ─────────────────────────────────────────────────────────

    def publish(self, url: str, content) -> httpx.Response:
        req = json.loads(content)
        authority = self._authority_for(url)
        ctx_id = f"acdp://{authority}/{uuid.uuid4()}"
        lineage_id = req.get("lineage_id") or f"lin:sha256:{uuid.uuid4().hex}"
        version = req.get("version") or len(self.lineages.get(lineage_id, [])) + 1
        created_at = datetime.now(timezone.utc).isoformat()

        body = {
            **req,
            "ctx_id": ctx_id,
            "lineage_id": lineage_id,
            "version": version,
            "created_at": created_at,
            "origin_registry": authority,
        }
        # The SDK serializes the context type under either key depending on
        # the builder; Body requires "type".
        body.setdefault("type", body.get("context_type", "data_snapshot"))
        self.contexts[ctx_id] = body
        self.lineages.setdefault(lineage_id, []).append(ctx_id)

        return httpx.Response(
            201,
            json={
                "ctx_id": ctx_id,
                "lineage_id": lineage_id,
                "version": version,
                "created_at": created_at,
                "status": "active",
            },
            request=httpx.Request("POST", url),
        )

    def _envelope(self, ctx_id: str) -> dict:
        return {
            "body": self.contexts[ctx_id],
            "registry_state": {"status": "active"},
            "registry_receipt": None,
        }

    def get(self, url: str) -> httpx.Response:
        req = httpx.Request("GET", url)
        path = httpx.URL(url).path
        if path.endswith("/healthz") or path.endswith("/readyz"):
            return httpx.Response(200, json={"ok": True}, request=req)
        if "/lineages/" in path:
            lineage_id = unquote(path.split("/lineages/", 1)[1])
            want_current = lineage_id.endswith("/current")
            if want_current:
                lineage_id = lineage_id.removesuffix("/current")
            ctx_ids = self.lineages.get(lineage_id)
            if not ctx_ids:
                return httpx.Response(
                    404,
                    json={"error": {"code": "not_found", "message": "no lineage"}},
                    request=req,
                )
            if want_current:
                return httpx.Response(200, json=self._envelope(ctx_ids[-1]), request=req)
            return httpx.Response(200, json=[self._envelope(c) for c in ctx_ids], request=req)
        if "/contexts/" in path:
            ctx_id = unquote(path.split("/contexts/", 1)[1]).removesuffix("/body")
            if ctx_id not in self.contexts:
                return httpx.Response(
                    404,
                    json={"error": {"code": "not_found", "message": "no context"}},
                    request=req,
                )
            return httpx.Response(200, json=self._envelope(ctx_id), request=req)
        return httpx.Response(
            404,
            json={"error": {"code": "not_found", "message": f"unhandled: {path}"}},
            request=req,
        )


@pytest.fixture()
def fake_registry(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setenv("CONTROL_PLANE_URL", "")
    get_settings.cache_clear()
    registry = FakeRegistry(get_settings())

    async def fake_post(self, url, content=None, headers=None, **kw):
        return registry.publish(str(url), content)

    async def fake_get(self, url, *args, **kw):
        return registry.get(str(url))

    with (
        patch.object(httpx.AsyncClient, "post", fake_post),
        patch.object(httpx.AsyncClient, "get", fake_get),
    ):
        yield registry
    get_settings.cache_clear()


async def _run(scenario_id: str):
    scenario = get_scenario(scenario_id)
    assert scenario is not None
    q: asyncio.Queue = asyncio.Queue()
    return await scenario.run(RunSpec(run_id=f"r-{scenario_id}", scenario_id=scenario_id), q)


async def test_s2_producer_consumer(fake_registry):
    res = await _run("s2_producer_consumer")
    assert res.status == "complete"
    assert len(res.contexts) == 2
    # The derivative was grounded in a real retrieve of the producer context.
    graph = res.lineage_graph
    assert len(graph.nodes) == 2
    assert graph.edges[0].src == res.contexts[0]
    assert graph.edges[0].dst == res.contexts[1]


async def test_s3_fanout(fake_registry):
    res = await _run("s3_fanout")
    assert res.status == "complete"
    # 1 producer + one derivative per default facet.
    facets = get_scenario("s3_fanout").default_inputs["facets"]
    assert len(res.contexts) == 1 + len(facets)
    graph = res.lineage_graph
    assert all(e.src == res.contexts[0] for e in graph.edges)
    assert len(graph.edges) == len(facets)


async def test_s4_chain(fake_registry):
    res = await _run("s4_chain")
    assert res.status == "complete"
    assert len(res.contexts) == 3
    # alpha→beta, alpha→gamma, beta→gamma
    pairs = {(e.src, e.dst) for e in res.lineage_graph.edges}
    a, b, c = res.contexts
    assert pairs == {(a, b), (a, c), (b, c)}


async def test_s5_cross_registry(fake_registry):
    res = await _run("s5_cross_registry")
    assert res.status == "complete"
    settings = get_settings()
    # The source landed on registry-a, the derivative on registry-b, and the
    # derivative's grounding retrieve was routed by authority.
    assert res.contexts[0].startswith(f"acdp://{settings.registry_a_authority}/")
    assert res.contexts[1].startswith(f"acdp://{settings.registry_b_authority}/")
    assert res.summary["cross_registry_edge"] is True


async def test_s7_supersession(fake_registry):
    res = await _run("s7_supersession")
    assert res.status == "complete"
    assert len(res.contexts) == 2
    assert res.summary["current_ctx_id"] == res.contexts[1]


async def test_s8_cross_org(fake_registry):
    res = await _run("s8_cross_org")
    assert res.status == "complete"
    settings = get_settings()
    assert res.contexts[0].startswith(f"acdp://{settings.registry_a_authority}/")
    assert res.contexts[1].startswith(f"acdp://{settings.registry_b_authority}/")
    assert res.summary["isolated_orgs"] is True
    assert res.lineage_graph.edges == []
