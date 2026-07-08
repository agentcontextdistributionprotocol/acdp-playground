"""Run lifecycle: emit start/complete events, persist results, forward to control plane."""

from __future__ import annotations

import asyncio
import logging
import traceback
from datetime import datetime, timezone
from typing import Final

from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.control_plane import get_control_plane
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

# Completed/in-flight run results, keyed by run_id.
_results: Final[dict[str, RunResult]] = {}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_result(run_id: str) -> RunResult | None:
    return _results.get(run_id)


async def execute(
    scenario: ScenarioDef,
    spec: RunSpec,
    events: asyncio.Queue[StepEvent],
) -> RunResult:
    settings = get_settings()
    cp = get_control_plane(settings)

    await events.put(
        StepEvent(
            type="run.started",
            run_id=spec.run_id,
            ts=_ts(),
            scenario_id=scenario.id,
        )
    )

    # Notify the control plane that the run started BEFORE running the scenario,
    # and crucially before the matching notify_run_complete below. Awaiting it
    # here (rather than firing it off independently from the API handler) makes
    # the start/complete pair strictly ordered within this one coroutine — so a
    # fast, publish-nothing scenario can't have its completion overtake its
    # start and 404 at the CP. _post is best-effort (no-op when CP is unset,
    # swallows transport errors), so this never breaks the run.
    await cp.notify_run_started(spec.run_id, scenario.id, spec.inputs)

    try:
        assert scenario.run is not None
        result = await scenario.run(spec, events)
    except Exception as e:  # noqa: BLE001 — we surface the error in the result
        tb = traceback.format_exc()
        log.exception("scenario %s failed", scenario.id)
        result = RunResult(
            run_id=spec.run_id,
            scenario_id=scenario.id,
            status="failed",
            error=f"{type(e).__name__}: {e}\n{tb}",
        )
        await events.put(
            StepEvent(
                type="run.error",
                run_id=spec.run_id,
                ts=_ts(),
                scenario_id=scenario.id,
                error=str(e),
            )
        )
    else:
        await events.put(
            StepEvent(
                type="run.complete",
                run_id=spec.run_id,
                ts=_ts(),
                scenario_id=scenario.id,
                contexts_produced=len(result.contexts),
                lineage_graph=(result.lineage_graph.model_dump() if result.lineage_graph else None),
            )
        )

    _results[spec.run_id] = result
    await cp.notify_run_complete(spec.run_id, result.status, result.model_dump())
    return result
