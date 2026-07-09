"""Tests for the new scenarios + the agent extended-body / supersede paths."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone


from acdp import AcdpProducer
from acdp_client.models import PublishResponse
from playground.agents.base import AgentTask, BasePlaygroundAgent


class _CapturingClient:
    """Fake AcdpClient recording every publish request body."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self._version = 0

    async def publish(self, request_json: str, *, idempotency_key=None):
        req = json.loads(request_json)
        self.requests.append(req)
        self._version += 1
        return PublishResponse(
            ctx_id=f"acdp://reg/ctx-{self._version}",
            lineage_id="lin:sha256:" + "a" * 64,
            version=req.get("version", self._version),
            created_at=datetime.now(timezone.utc),
            status="active",
        )


class _StubAgent(BasePlaygroundAgent):
    framework = "stub"

    async def call_llm(self, prompt: str) -> str:
        return "stub-result"


def _agent(client) -> _StubAgent:
    producer = AcdpProducer.from_seed(
        bytes(range(32)),
        "did:web:reg:agents:stub",
        "did:web:reg:agents:stub#key-1",
    )
    return _StubAgent(producer, client, asyncio.Queue(), "run-1", slug="stub")


async def test_publish_threads_extended_body_fields():
    client = _CapturingClient()
    agent = _agent(client)
    await agent.run(
        AgentTask(
            prompt="x",
            title="T",
            context_type="analysis",
            data_refs=[{"type": "primary_result", "location": "https://e.com/d.csv"}],
            data_period={"start": "2026-01-01T00:00:00Z", "end": "2026-03-31T23:59:59Z"},
            expires_at="2026-12-31T00:00:00Z",
            contributors=["did:web:reg:agents:helper"],
        )
    )
    req = client.requests[0]
    assert req["data_refs"][0]["type"] == "primary_result"
    assert req["data_period"]["start"] == "2026-01-01T00:00:00Z"
    assert req["expires_at"].startswith("2026-12-31")
    assert "did:web:reg:agents:helper" in req["contributors"]


async def test_supersede_carries_lineage_and_bumps_version():
    client = _CapturingClient()
    agent = _agent(client)
    # build_supersede_request needs a full registry-style body: assemble one
    # from a v1 publish request plus the fields the registry assigns.
    v1 = json.loads(
        agent.producer.build_publish_request(
            title="v1", context_type="data_snapshot", summary="first"
        )
    )
    guard = "lin:sha256:" + "b" * 64
    previous_body = {
        **v1,
        "ctx_id": "acdp://reg/00000000-0000-4000-8000-000000000001",
        "lineage_id": "lin:sha256:" + "a" * 64,
        "origin_registry": "reg",
        "created_at": "2026-06-01T00:00:00.000Z",
    }
    out = await agent.supersede(
        json.dumps(previous_body),
        AgentTask(prompt="", title="v2", context_type="data_snapshot"),
        "second",
        expected_lineage_id=guard,
    )
    # The superseding request bumps to v2 and pins the expected lineage
    # (the SDK writes the guard into the request's lineage_id field).
    v2 = client.requests[-1]
    assert v2["version"] == 2
    assert v2["lineage_id"] == guard
    assert out.version == 2


def test_publish_omits_empty_extended_fields():
    """No data_refs/period/expires_at → those keys absent (stable hash preimage)."""
    client = _CapturingClient()
    agent = _agent(client)
    kwargs = agent._publish_kwargs(AgentTask(prompt="x", title="T", context_type="analysis"), "res")
    assert "data_refs" not in kwargs
    assert "data_period" not in kwargs
    assert "expires_at" not in kwargs
