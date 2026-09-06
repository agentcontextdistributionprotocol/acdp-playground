"""S18 — idempotent publish (at-most-once under a repeated key).

The registry now claims the idempotency record *first* (INSERT … ON CONFLICT
DO NOTHING) before persisting a context, so two publishes carrying the same
``Idempotency-Key`` can never produce two contexts — the second call replays
the first's stored response (registry acdp-registry-rs #24). The key is
accepted at 1–256 characters; an out-of-range value is treated as **absent**
(the publish still succeeds, just without idempotency) rather than rejected.

This scenario drives the live registry when it's up: one agent publishes a
context with a fixed key, then re-sends the *same* request with the *same*
key, and we assert a single ``ctx_id`` came back both times (the replay). When
the registry is absent — the playground's degrade-gracefully constraint — it
records a note and completes; the hard contract (duplicate key → one ctx,
key-length handling) is pinned offline in ``tests/test_idempotency.py``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

from acdp_client import AcdpHTTPError
from acdp_client.models import StepEvent
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s18_idempotency",
    name="Idempotent publish",
    description="Re-sending a publish with the same Idempotency-Key replays the "
    "first response — one context, never two (registry #24). "
    "Degrades gracefully without the registry.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "quarterly forecast"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    # Stable within the run, distinct across runs (run_id rotates).
    idem_key = f"s18-{spec.run_id}"

    async def note(title: str, preview: str) -> None:
        await events.put(
            StepEvent(
                type="scenario.note",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                title=title,
                preview=preview,
            )
        )

    summary: dict = {"degraded": False, "idempotency_key": idem_key}
    try:
        agent = make_langchain_agent(
            spec, events, bundle, slug="publisher", registry="a", method="did:key"
        )

        # One signed request body, reused verbatim for both sends.
        request_json = agent.producer.build_publish_request(
            title=f"{topic} — idempotent",
            context_type="data_snapshot",
            visibility="public",
            summary="A context published twice under one idempotency key.",
            metadata=json.dumps({"run_id": spec.run_id, "scenario": SCENARIO.id}),
        )

        try:
            first = await agent.client.publish(request_json, idempotency_key=idem_key)
            await agent._emit("acdp.publish", ctx_id=first.ctx_id, title=f"{topic} — idempotent")
            # Re-send the identical request under the identical key.
            second = await agent.client.publish(request_json, idempotency_key=idem_key)
        except AcdpHTTPError as e:
            log.warning("S18 publish failed (registry down?): %s", e)
            summary["degraded"] = True
            await note("degraded", f"registry unavailable: {e.status}")
            return RunResult(
                run_id=spec.run_id,
                scenario_id=SCENARIO.id,
                status="complete",
                contexts=[],
                summary=summary,
                error=None,
            )
        except Exception as e:  # noqa: BLE001 — transport down → degrade
            log.warning("S18 publish failed (registry down?): %s", e)
            summary["degraded"] = True
            await note("degraded", f"registry unavailable: {type(e).__name__}")
            return RunResult(
                run_id=spec.run_id,
                scenario_id=SCENARIO.id,
                status="complete",
                contexts=[],
                summary=summary,
                error=None,
            )

        replayed = first.ctx_id == second.ctx_id
        summary.update(
            {
                "first_ctx": first.ctx_id,
                "second_ctx": second.ctx_id,
                "replayed": replayed,
            }
        )
        await note(
            "idempotent replay",
            f"replayed={replayed} ctx={first.ctx_id}",
        )

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if replayed else "failed",
            contexts=[first.ctx_id],
            summary=summary,
            error=None if replayed else "S18: duplicate Idempotency-Key produced two contexts",
        )
    finally:
        await bundle.aclose()
