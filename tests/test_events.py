"""Unit tests for the in-process SSE event bus (playground.events)."""

from __future__ import annotations

from acdp_client.models import StepEvent
from playground.events import create_queue, drop_queue, get_queue, publish


def _step(run_id: str) -> StepEvent:
    return StepEvent(type="scenario.note", run_id=run_id, ts="2026-06-10T00:00:00Z")


def test_create_queue_is_idempotent():
    run_id = "evt-run-create"
    try:
        q1 = create_queue(run_id)
        q2 = create_queue(run_id)
        assert q1 is q2  # same run_id returns the same queue, not a fresh one
        assert get_queue(run_id) is q1
    finally:
        drop_queue(run_id)


def test_get_queue_unknown_returns_none():
    assert get_queue("never-created") is None


def test_drop_queue_is_safe_when_absent():
    drop_queue("never-created")  # no KeyError


async def test_publish_delivers_to_matching_queue():
    run_id = "evt-run-deliver"
    queue = create_queue(run_id)
    try:
        await publish(_step(run_id))
        got = queue.get_nowait()
        assert got.run_id == run_id
        assert got.type == "scenario.note"
    finally:
        drop_queue(run_id)


async def test_publish_to_unknown_run_is_dropped_silently():
    # No queue for this run_id → publish must not raise.
    await publish(_step("no-such-run"))


async def test_dropped_queue_no_longer_receives():
    run_id = "evt-run-dropped"
    queue = create_queue(run_id)
    drop_queue(run_id)
    await publish(_step(run_id))  # bus has forgotten the run
    assert queue.empty()


async def test_sse_disconnect_mid_run_keeps_queue_and_run_visible():
    """Regression for #92: a client dropping the stream must not 404 the run."""
    from playground.api.runs import get_run, stream_events

    class _Req:
        def __init__(self) -> None:
            self.calls = 0

        async def is_disconnected(self) -> bool:
            self.calls += 1
            return self.calls > 1  # connected for one event, then gone

    async def _drain(resp) -> str:
        return "".join([c async for c in resp.body_iterator])

    run_id = "run-92-disconnect"
    queue = create_queue(run_id)
    queue.put_nowait(StepEvent(type="run.started", run_id=run_id, ts="2026-01-01T00:00:00Z"))
    try:
        body = await _drain(await stream_events(run_id, _Req()))
        assert "run.started" in body
        # stream ended before run.complete: queue and run must survive
        assert get_queue(run_id) is queue
        assert (await get_run(run_id))["status"] == "running"

        # a reconnect resumes; the terminal event delivers and drops the queue
        queue.put_nowait(StepEvent(type="run.complete", run_id=run_id, ts="2026-01-01T00:00:01Z"))
        body = await _drain(
            await stream_events(run_id, type("R", (), {"is_disconnected": lambda s: _false()})())
        )
        assert "run.complete" in body
        assert get_queue(run_id) is None
    finally:
        drop_queue(run_id)


async def _false() -> bool:
    return False


async def test_sse_reconnect_after_lost_terminal_event_replays_result():
    from playground.api.runs import stream_events
    from playground.scenarios.models import RunResult
    from playground.scenarios.runner import _results

    run_id = "run-92-lost-terminal"
    create_queue(run_id)  # drained: the terminal event was lost on disconnect
    _results[run_id] = RunResult(run_id=run_id, scenario_id="s1", status="complete")
    try:
        resp = await stream_events(run_id, None)
        body = "".join([c async for c in resp.body_iterator])
        assert "event: end" in body
        assert get_queue(run_id) is None
    finally:
        drop_queue(run_id)
        _results.pop(run_id, None)
