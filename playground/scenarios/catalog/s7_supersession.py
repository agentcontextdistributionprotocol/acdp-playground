"""S7 — supersession. Same agent publishes v1, then v2 on the same lineage
via the SDK's real supersede path (``build_supersede_request`` /
``agent.supersede``). We then query the lineage and current endpoints to
confirm both versions are visible on one lineage and v2 is current.
"""

from __future__ import annotations

import asyncio
import json

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
        agent = make_langchain_agent(spec, events, bundle, slug="curator", method="did:key")

        v1 = await agent.run(
            AgentTask(
                prompt=f"Draft a 3-bullet v1 of the {topic}.",
                title=f"{topic} — v1",
                context_type="data_snapshot",
                tags=["draft", "v1"],
                metadata={"version_label": "v1"},
            )
        )

        # v2 supersedes v1 for real: fetch v1's registry-assigned body so we
        # have the exact bytes build_supersede_request needs, draft v2
        # grounded on v1's actual summary, then publish through the SDK's
        # supersede path so v2 lands on v1's own lineage with the version
        # auto-incremented (not a second, unrelated publish).
        v1_full = await agent.client.retrieve_raw(v1.ctx_id)
        previous_body = json.dumps(v1_full["body"])

        prompt = (
            "Revise this v1 draft into a sharper v2 with one extra bullet:"
            f"\n\n{v1_full['body'].get('summary', '')}"
        )
        await agent._emit("llm.thinking", preview=prompt[:100])
        llm_result = await agent.call_llm(prompt)

        v2 = await agent.supersede(
            previous_body,
            AgentTask(
                prompt=prompt,
                title=f"{topic} — v2",
                context_type="data_snapshot",
                tags=["draft", "v2"],
                metadata={"version_label": "v2"},
            ),
            llm_result,
        )

        same_lineage = v2.lineage_id == v1.lineage_id

        # Real lineage + current queries, unguarded. S7 isn't on CLAUDE.md's
        # degradation exception list (only S10 is), so a registry failure
        # here should fail the run loudly via run.error, not be silently
        # absorbed into a degraded-but-"complete" result.
        lineage = await agent.client.lineage(v1.lineage_id)
        lineage_len = len(lineage)
        current = await agent.client.current(v1.lineage_id)
        current_ctx_id = current.body.ctx_id

        ok = same_lineage and lineage_len == 2 and current_ctx_id == v2.ctx_id

        auth = settings.registry_a_authority
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if ok else "failed",
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
            summary={
                "same_lineage": same_lineage,
                "lineage_length": lineage_len,
                "current_ctx_id": current_ctx_id,
            },
            error=None if ok else "S7 supersession assertions failed",
        )
    finally:
        await bundle.aclose()
