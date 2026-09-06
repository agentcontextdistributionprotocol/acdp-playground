"""S4 — linear chain A → B → C, with C deriving from both A and B."""

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
    id="s4_chain",
    name="Linear Chain A → B → C",
    description="Each agent grounds on the previous agent's published context. "
    "Agent C grounds on both A and B. Lineage query reconstructs "
    "the full DAG.",
    registry_mode="single",
    agent_count=3,
    framework="langchain",
    default_inputs={"topic": "global semiconductor supply chains"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        a = make_langchain_agent(spec, events, bundle, slug="agent-alpha", method="did:key")
        b = make_langchain_agent(spec, events, bundle, slug="agent-beta", method="did:key")
        c = make_langchain_agent(spec, events, bundle, slug="agent-gamma", method="did:key")

        out_a = await a.run(
            AgentTask(
                prompt=f"Research and summarize the top 5 risks in {topic}. "
                f"Be specific and cite recent trends.",
                title=f"Risk landscape — {topic}",
                context_type="data_snapshot",
                domain="supply_chain",
                tags=["research", "risk"],
            )
        )

        out_b = await b.run(
            AgentTask(
                prompt=f"Based on the risk analysis, identify the top 3 investment "
                f"opportunities in {topic}.",
                title=f"Investment opportunities — {topic}",
                context_type="analysis",
                domain="supply_chain",
                tags=["investment", "analysis"],
                derived_from=[out_a.ctx_id],
            )
        )

        out_c = await c.run(
            AgentTask(
                prompt=f"Draft a 3-paragraph executive recommendation for a CFO "
                f"considering exposure to {topic}.",
                title=f"CFO recommendation — {topic}",
                context_type="analysis",
                domain="supply_chain",
                tags=["recommendation", "executive"],
                derived_from=[out_a.ctx_id, out_b.ctx_id],
            )
        )

        auth = settings.registry_a_authority
        nodes = [
            LineageNode(
                ctx_id=out_a.ctx_id,
                agent_id=a.agent_did,
                title=out_a.title,
                context_type="data_snapshot",
                registry_authority=auth,
                step=1,
            ),
            LineageNode(
                ctx_id=out_b.ctx_id,
                agent_id=b.agent_did,
                title=out_b.title,
                context_type="analysis",
                registry_authority=auth,
                step=2,
            ),
            LineageNode(
                ctx_id=out_c.ctx_id,
                agent_id=c.agent_did,
                title=out_c.title,
                context_type="analysis",
                registry_authority=auth,
                step=3,
            ),
        ]
        edges = [
            LineageEdge(src=out_a.ctx_id, dst=out_b.ctx_id),
            LineageEdge(src=out_a.ctx_id, dst=out_c.ctx_id),
            LineageEdge(src=out_b.ctx_id, dst=out_c.ctx_id),
        ]
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            contexts=[out_a.ctx_id, out_b.ctx_id, out_c.ctx_id],
            lineage_graph=LineageGraph(nodes=nodes, edges=edges),
        )
    finally:
        await bundle.aclose()
