"""S3 — one producer, N consumers all deriving from the same context."""

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
    id="s3_fanout",
    name="Fan-out (1 → N)",
    description="One producer publishes a base context. Three consumers run in "
    "parallel, each producing a domain-specific derivative.",
    registry_mode="single",
    agent_count=4,
    framework="langchain",
    default_inputs={
        "topic": "GLP-1 drug pipeline",
        "facets": ["clinical-trial outcomes", "manufacturing capacity", "payer dynamics"],
    },
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    facets: list[str] = spec.inputs.get("facets", SCENARIO.default_inputs["facets"])

    try:
        producer = make_langchain_agent(spec, events, bundle, slug="producer", method="did:key")
        consumers = [
            make_langchain_agent(spec, events, bundle, slug=f"facet-{i}", method="did:key")
            for i in range(len(facets))
        ]

        prod_out = await producer.run(
            AgentTask(
                prompt=f"Write a structured brief on {topic}. Include market size, "
                f"key players, and unknowns.",
                title=f"Brief — {topic}",
                context_type="data_snapshot",
                domain="pharma",
                tags=["brief", "raw"],
            )
        )

        async def make_derivative(consumer, facet: str):
            return await consumer.run(
                AgentTask(
                    prompt=f"From the brief, write a 4-sentence analysis focused on '{facet}'.",
                    title=f"Facet ({facet}) — {topic}",
                    context_type="analysis",
                    domain="pharma",
                    tags=["facet", facet.split()[0]],
                    derived_from=[prod_out.ctx_id],
                )
            )

        deriv_outs = await asyncio.gather(
            *(make_derivative(c, f) for c, f in zip(consumers, facets))
        )

        auth = settings.registry_a_authority
        nodes = [
            LineageNode(
                ctx_id=prod_out.ctx_id,
                agent_id=producer.agent_did,
                title=prod_out.title,
                context_type="data_snapshot",
                registry_authority=auth,
                step=1,
            )
        ]
        edges: list[LineageEdge] = []
        for i, out in enumerate(deriv_outs):
            nodes.append(
                LineageNode(
                    ctx_id=out.ctx_id,
                    agent_id=consumers[i].agent_did,
                    title=out.title,
                    context_type="analysis",
                    registry_authority=auth,
                    step=2,
                )
            )
            edges.append(LineageEdge(src=prod_out.ctx_id, dst=out.ctx_id))

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            contexts=[prod_out.ctx_id] + [o.ctx_id for o in deriv_outs],
            lineage_graph=LineageGraph(nodes=nodes, edges=edges),
        )
    finally:
        await bundle.aclose()
