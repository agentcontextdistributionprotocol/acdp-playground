"""S1 — single agent publishes one context."""

from __future__ import annotations

import asyncio

from acdp_client.models import StepEvent

from playground.agents.base import AgentTask
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

SCENARIO = ScenarioDef(
    id="s1_single_publish",
    name="Single Publish",
    description="One agent publishes one context. Smallest possible round-trip "
    "through the SDK + registry.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "quarterly cash flow"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        agent = make_langchain_agent(
            spec, events, bundle, slug="solo", registry="a", method="did:key"
        )
        out = await agent.run(
            AgentTask(
                prompt=f"Summarize three notable trends in {topic} in 4 sentences.",
                title=f"{topic} — notable trends",
                context_type="data_snapshot",
                domain="finance",
                tags=["trends", "summary"],
            )
        )
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            contexts=[out.ctx_id],
            lineage_graph=LineageGraph(
                nodes=[
                    LineageNode(
                        ctx_id=out.ctx_id,
                        agent_id=agent.agent_did,
                        title=out.title,
                        context_type="data_snapshot",
                        registry_authority=settings.registry_a_authority,
                        step=1,
                    )
                ],
                edges=[],
            ),
            summary={"agent": agent.agent_did, "ctx_id": out.ctx_id},
        )
    finally:
        await bundle.aclose()
