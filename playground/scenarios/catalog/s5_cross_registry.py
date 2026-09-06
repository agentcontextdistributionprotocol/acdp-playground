"""S5 — cross-registry chain: A publishes to registry-a, B retrieves cross-
registry and publishes to registry-b. The lineage edge crosses authorities.
"""

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
    id="s5_cross_registry",
    name="Cross-Registry Chain",
    description="Agent A publishes to registry-a; agent B (on registry-b) "
    "retrieves cross-registry and publishes a derivative. Verifies "
    "cross-registry resolution and that lineage edges span "
    "authorities.",
    registry_mode="dual",
    agent_count=2,
    framework="langchain",
    default_inputs={"topic": "Arctic shipping routes"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        agent_a = make_langchain_agent(
            spec, events, bundle, slug="cross-a", registry="a", method="did:key"
        )
        agent_b = make_langchain_agent(
            spec, events, bundle, slug="cross-b", registry="b", method="did:key"
        )

        out_a = await agent_a.run(
            AgentTask(
                prompt=f"Write 5 bullet points on {topic} (geopolitical risks).",
                title=f"Cross-registry source — {topic}",
                context_type="data_snapshot",
                domain="geopolitics",
                tags=["cross-registry", "source"],
            )
        )

        # Agent B is on registry-b but derives_from a registry-a context.
        # AcdpClient.resolve uses the authority_map to fetch from registry-a.
        out_b = await agent_b.run(
            AgentTask(
                prompt="Given the source, write a 4-sentence analysis of "
                "shipping investment implications.",
                title=f"Cross-registry derivative — {topic}",
                context_type="analysis",
                domain="geopolitics",
                tags=["cross-registry", "derivative"],
                derived_from=[out_a.ctx_id],
            )
        )

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            contexts=[out_a.ctx_id, out_b.ctx_id],
            lineage_graph=LineageGraph(
                nodes=[
                    LineageNode(
                        ctx_id=out_a.ctx_id,
                        agent_id=agent_a.agent_did,
                        title=out_a.title,
                        context_type="data_snapshot",
                        registry_authority=settings.registry_a_authority,
                        step=1,
                    ),
                    LineageNode(
                        ctx_id=out_b.ctx_id,
                        agent_id=agent_b.agent_did,
                        title=out_b.title,
                        context_type="analysis",
                        registry_authority=settings.registry_b_authority,
                        step=2,
                    ),
                ],
                edges=[LineageEdge(src=out_a.ctx_id, dst=out_b.ctx_id)],
            ),
            summary={"cross_registry_edge": True},
        )
    finally:
        await bundle.aclose()
