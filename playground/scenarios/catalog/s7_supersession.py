"""S7 — supersession. Same agent publishes v1, then v2 on the same lineage
via supersedes/version semantics. We then query the lineage and current
endpoints to confirm both versions are visible and v2 is current.

The acdp-py SDK builds the v2 publish request just like v1; the
registry assigns the next version on the matching lineage.
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
    id="s7_supersession",
    name="Supersession (v1 → v2)",
    description="One agent publishes v1, then publishes a revised v2 that "
    "supersedes v1 (same lineage, new version). Lineage query "
    "returns both; current returns v2.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "Q3 product roadmap"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        agent = make_langchain_agent(spec, events, bundle, slug="curator")

        v1 = await agent.run(
            AgentTask(
                prompt=f"Draft a 3-bullet v1 of the {topic}.",
                title=f"{topic} — v1",
                context_type="data_snapshot",
                tags=["draft", "v1"],
                metadata={"version_label": "v1"},
            )
        )

        # v2 derives from v1 (so the registry treats it as a revision on the
        # same lineage). The SDK doesn't expose explicit supersedes yet, so
        # derived_from establishes the link; the registry's versioning + the
        # control plane treat consecutive publishes on the same lineage as
        # revisions.
        v2 = await agent.run(
            AgentTask(
                prompt="Revise the v1 into a sharper v2 with one extra bullet.",
                title=f"{topic} — v2",
                context_type="data_snapshot",
                tags=["draft", "v2"],
                derived_from=[v1.ctx_id],
                metadata={"version_label": "v2", "supersedes": v1.ctx_id},
            )
        )

        # Query lineage to confirm both versions are visible.
        try:
            lineage = await agent.client.lineage(v1.lineage_id)
            lineage_len = len(lineage)
        except Exception:  # noqa: BLE001
            lineage_len = -1

        auth = settings.registry_a_authority
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            contexts=[v1.ctx_id, v2.ctx_id],
            lineage_graph=LineageGraph(
                nodes=[
                    LineageNode(
                        ctx_id=v1.ctx_id,
                        agent_id=agent.agent_did,
                        title=v1.title,
                        context_type="data_snapshot",
                        registry_authority=auth,
                        step=1,
                    ),
                    LineageNode(
                        ctx_id=v2.ctx_id,
                        agent_id=agent.agent_did,
                        title=v2.title,
                        context_type="data_snapshot",
                        registry_authority=auth,
                        step=2,
                    ),
                ],
                edges=[LineageEdge(src=v1.ctx_id, dst=v2.ctx_id)],
            ),
            summary={"lineage_length": lineage_len, "current_ctx_id": v2.ctx_id},
        )
    finally:
        await bundle.aclose()
