"""S8 — cross-org isolation. Org A on registry-a publishes one context;
org B on registry-b publishes an independent context. Both are visible
to the control plane (when wired), but the agents never reference each
other.

Demonstrates that authorities are independent — the playground spawns
two organizations with no shared identity material.
"""

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
    id="s8_cross_org",
    name="Cross-Org Isolation",
    description="Two organizations publish independently on different "
    "registries. No cross-references — verifies that authorities "
    "are isolated and the control plane sees both sides without "
    "merging identities.",
    registry_mode="cross_org",
    agent_count=2,
    framework="langchain",
    default_inputs={
        "topic_org_a": "European market entry",
        "topic_org_b": "Asia-Pacific supply contracts",
    },
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic_a = spec.inputs.get("topic_org_a", SCENARIO.default_inputs["topic_org_a"])
    topic_b = spec.inputs.get("topic_org_b", SCENARIO.default_inputs["topic_org_b"])

    try:
        org_a = make_langchain_agent(
            spec, events, bundle, slug="org-a", registry="a", method="did:key"
        )
        org_b = make_langchain_agent(
            spec, events, bundle, slug="org-b", registry="b", method="did:key"
        )

        out_a, out_b = await asyncio.gather(
            org_a.run(
                AgentTask(
                    prompt=f"3 bullets on {topic_a}.",
                    title=f"Org A — {topic_a}",
                    context_type="data_snapshot",
                    tags=["org-a"],
                )
            ),
            org_b.run(
                AgentTask(
                    prompt=f"3 bullets on {topic_b}.",
                    title=f"Org B — {topic_b}",
                    context_type="data_snapshot",
                    tags=["org-b"],
                )
            ),
        )

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            contexts=[out_a.ctx_id, out_b.ctx_id],
            lineage_graph=LineageGraph(
                nodes=[
                    LineageNode(
                        ctx_id=out_a.ctx_id,
                        agent_id=org_a.agent_did,
                        title=out_a.title,
                        context_type="data_snapshot",
                        registry_authority=settings.registry_a_authority,
                        step=1,
                    ),
                    LineageNode(
                        ctx_id=out_b.ctx_id,
                        agent_id=org_b.agent_did,
                        title=out_b.title,
                        context_type="data_snapshot",
                        registry_authority=settings.registry_b_authority,
                        step=1,
                    ),
                ],
                edges=[],
            ),
            summary={"isolated_orgs": True},
        )
    finally:
        await bundle.aclose()
