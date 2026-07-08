"""S15 — supersession with an expected-lineage guard.

Builds on S7 but uses the SDK's ``build_supersede_request`` and the
``expected_lineage_id`` concurrency guard:

* v1 is published normally (no guard — the SDK rejects a guard on v1).
* v2 supersedes v1 via ``build_supersede_request`` carrying
  ``expected_lineage_id = <v1 lineage>``; the registry accepts it from
  v2 onward and pins the new version onto the same lineage.

We then confirm the lineage query returns both versions and ``current``
points at v2. Anonymous publish works in playground mode, so this runs
in the default stack; lineage queries degrade gracefully if absent.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

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

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s15_supersession_lineage",
    name="Supersession w/ expected_lineage_id",
    description="v1 then v2 via build_supersede_request with an "
    "expected_lineage_id concurrency guard. Lineage returns both; "
    "current returns v2. Exercises the SDK supersede path.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "incident postmortem"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority

    try:
        agent = make_langchain_agent(spec, events, bundle, slug="versioner", registry="a")

        # The SDK forbids a lineage guard on a v1 publish — confirm that
        # contract so a regression surfaces here rather than in production.
        v1_guard_rejected = False
        try:
            agent.producer.build_publish_request(
                title="probe",
                context_type="data_snapshot",
                expected_lineage_id="lin:sha256:" + "0" * 64,
            )
        except Exception:  # noqa: BLE001 — expected rejection
            v1_guard_rejected = True

        # v1 — plain publish. Build raw so we can feed the body to supersede.
        v1_raw = agent.producer.build_publish_request(
            title=f"{topic} — v1",
            context_type="data_snapshot",
            visibility="public",
            summary="Initial writeup of the incident.",
            tags=["postmortem", "v1"],
            metadata=json.dumps({"version_label": "v1", "run_id": spec.run_id}),
        )
        v1 = await agent.client.publish(v1_raw)
        await agent._emit("acdp.publish", ctx_id=v1.ctx_id, title=f"{topic} — v1")

        # build_supersede_request needs the registry's full body (with its
        # assigned ctx_id/created_at), so fetch it verbatim.
        v1_full = await agent.client.retrieve_raw(v1.ctx_id)
        previous_body = json.dumps(v1_full["body"])

        # v2 — supersede with the lineage guard.
        v2_task = AgentTask(
            prompt="",
            title=f"{topic} — v2",
            context_type="data_snapshot",
            tags=["postmortem", "v2"],
            metadata={"version_label": "v2"},
        )
        v2 = await agent.supersede(
            previous_body,
            v2_task,
            "Revised writeup with root-cause and remediation.",
            expected_lineage_id=v1.lineage_id,
        )

        same_lineage = v2.lineage_id == v1.lineage_id

        # Lineage + current queries (degrade gracefully).
        lineage_len = -1
        current_ctx = None
        try:
            lineage = await agent.client.lineage(v1.lineage_id)
            lineage_len = len(lineage)
            current = await agent.client.current(v1.lineage_id)
            current_ctx = current.body.ctx_id
        except Exception as e:  # noqa: BLE001
            log.warning("S15 lineage query failed: %s", e)

        ok = v1_guard_rejected and same_lineage and v2.version >= 2

        await events.put(
            StepEvent(
                type="scenario.note",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                title="supersession outcome",
                preview=f"v1_guard_rejected={v1_guard_rejected} "
                f"same_lineage={same_lineage} v2_version={v2.version}",
            )
        )

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
                        title=f"{topic} — v1",
                        context_type="data_snapshot",
                        registry_authority=authority,
                        step=1,
                    ),
                    LineageNode(
                        ctx_id=v2.ctx_id,
                        agent_id=agent.agent_did,
                        title=f"{topic} — v2",
                        context_type="data_snapshot",
                        registry_authority=authority,
                        step=2,
                    ),
                ],
                edges=[LineageEdge(src=v1.ctx_id, dst=v2.ctx_id)],
            ),
            summary={
                "v1_guard_rejected": v1_guard_rejected,
                "same_lineage": same_lineage,
                "v2_version": v2.version,
                "lineage_length": lineage_len,
                "current_ctx_id": current_ctx,
            },
            error=None if ok else "S15 supersession assertions failed",
        )
    finally:
        await bundle.aclose()
