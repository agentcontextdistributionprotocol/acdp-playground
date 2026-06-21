"""Run-lifecycle tests for playground.scenarios.runner.execute.

execute() is the harness that wraps a scenario's run(): it emits run.started,
invokes the scenario, then emits run.complete or run.error, and persists the
RunResult for later GET /runs/{id}. The control-plane bridge is a no-op here
(CONTROL_PLANE_URL unset by default), so this is fully offline.
"""

from __future__ import annotations

import asyncio

from playground.scenarios.models import LineageGraph, RunResult, RunSpec, ScenarioDef
from playground.scenarios.runner import execute, get_result


def _spec(run_id: str) -> RunSpec:
    return RunSpec(run_id=run_id, scenario_id="unit")


def _scenario(run_fn) -> ScenarioDef:
    return ScenarioDef(
        id="unit", name="Unit", description="runner unit test", run=run_fn
    )


def test_get_result_unknown_run_is_none():
    assert get_result("never-ran") is None


async def test_execute_success_emits_started_then_complete_and_persists():
    run_id = "runner-ok"

    async def run(spec: RunSpec, events: asyncio.Queue) -> RunResult:
        return RunResult(
            run_id=spec.run_id,
            scenario_id=spec.scenario_id,
            status="complete",
            contexts=["acdp://reg/1"],
            lineage_graph=LineageGraph(),
        )

    queue: asyncio.Queue = asyncio.Queue()
    result = await execute(_scenario(run), _spec(run_id), queue)

    assert result.status == "complete"
    # Events: run.started first, run.complete last (carrying the context count).
    started = queue.get_nowait()
    complete = queue.get_nowait()
    assert started.type == "run.started"
    assert complete.type == "run.complete"
    assert complete.contexts_produced == 1
    assert complete.lineage_graph is not None
    # Result is retrievable by run_id afterwards.
    assert get_result(run_id) is result


async def test_execute_notifies_cp_start_before_complete(monkeypatch):
    """Regression: a fast, publish-nothing run must notify the CP of its start
    BEFORE its completion. The two were previously fired as independent tasks,
    so completion could overtake the start and 404 at the CP (run stuck
    "running"). execute() now awaits run-started ahead of the scenario."""
    calls: list[str] = []

    class _RecordingCP:
        async def notify_run_started(self, run_id, scenario_id, inputs):
            calls.append("started")

        async def notify_run_complete(self, run_id, status, result):
            calls.append("complete")

    monkeypatch.setattr(
        "playground.scenarios.runner.get_control_plane", lambda _settings: _RecordingCP()
    )

    async def run(spec: RunSpec, events: asyncio.Queue) -> RunResult:
        # Publishes nothing and returns immediately — the worst case for the race.
        return RunResult(run_id=spec.run_id, scenario_id=spec.scenario_id, status="complete")

    await execute(_scenario(run), _spec("runner-order"), asyncio.Queue())
    assert calls == ["started", "complete"]


async def test_execute_failure_emits_error_and_persists_failed_result():
    run_id = "runner-boom"

    async def run(spec: RunSpec, events: asyncio.Queue) -> RunResult:
        raise ValueError("kaboom")

    queue: asyncio.Queue = asyncio.Queue()
    result = await execute(_scenario(run), _spec(run_id), queue)

    assert result.status == "failed"
    assert "kaboom" in result.error
    assert "ValueError" in result.error  # traceback is captured

    started = queue.get_nowait()
    err = queue.get_nowait()
    assert started.type == "run.started"
    assert err.type == "run.error"
    assert err.error == "kaboom"
    assert get_result(run_id) is result
