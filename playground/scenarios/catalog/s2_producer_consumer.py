"""S2 — producer agent publishes, consumer agent retrieves + publishes a derivative."""

from __future__ import annotations

import asyncio

from acdp_client.models import StepEvent
from playground.agents.base import AgentTask
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.scenarios.models import (
    LineageEdge,
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

SCENARIO = ScenarioDef(
    id="s2_producer_consumer",
    name="Producer → Consumer",
    description="One agent publishes raw data; a second agent retrieves it, "
    "analyses it, and publishes a derivative tagged "
    "derived_from=[producer].",
    registry_mode="single",
    agent_count=2,
    framework="langchain",
    default_inputs={"topic": "renewable energy capacity by region"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        producer = make_langchain_agent(spec, events, bundle, slug="producer", method="did:key")
        consumer = make_langchain_agent(spec, events, bundle, slug="consumer", method="did:key")

        prod_out = await producer.run(
            AgentTask(
                prompt=f"List 5 datapoints about {topic}. Be specific.",
                title=f"Raw data — {topic}",
                context_type="data_snapshot",
                tags=["raw", "data"],
                domain="energy",
            )
        )

        cons_out = await consumer.run(
            AgentTask(
                prompt="Given the raw data, produce a 3-bullet executive analysis.",
                title=f"Analysis — {topic}",
                context_type="analysis",
                tags=["analysis"],
                domain="energy",
                derived_from=[prod_out.ctx_id],
            )
        )

        auth = settings.registry_a_authority
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            contexts=[prod_out.ctx_id, cons_out.ctx_id],
            lineage_graph=LineageGraph(
                nodes=[
                    LineageNode(
                        ctx_id=prod_out.ctx_id,
                        agent_id=producer.agent_did,
                        title=prod_out.title,
                        context_type="data_snapshot",
                        registry_authority=auth,
                        step=1,
                    ),
                    LineageNode(
                        ctx_id=cons_out.ctx_id,
                        agent_id=consumer.agent_did,
                        title=cons_out.title,
                        context_type="analysis",
                        registry_authority=auth,
                        step=2,
                    ),
                ],
                edges=[LineageEdge(src=prod_out.ctx_id, dst=cons_out.ctx_id)],
            ),
        )
    finally:
        await bundle.aclose()
