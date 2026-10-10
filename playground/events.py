"""In-process SSE event bus.

One ``asyncio.Queue`` per run_id. Queues are created when a run starts
and removed once an SSE consumer has been delivered the terminal event
(``run.complete``/``run.error``). A consumer disconnecting mid-run leaves it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Final

from acdp_client.models import StepEvent

log = logging.getLogger(__name__)

# run_id -> queue
_event_bus: Final[dict[str, asyncio.Queue[StepEvent]]] = {}


def create_queue(run_id: str) -> asyncio.Queue[StepEvent]:
    if run_id in _event_bus:
        return _event_bus[run_id]
    q: asyncio.Queue[StepEvent] = asyncio.Queue()
    _event_bus[run_id] = q
    return q


def get_queue(run_id: str) -> asyncio.Queue[StepEvent] | None:
    return _event_bus.get(run_id)


def drop_queue(run_id: str) -> None:
    _event_bus.pop(run_id, None)


async def publish(event: StepEvent) -> None:
    q = _event_bus.get(event.run_id)
    if q is None:
        log.debug("dropping event for unknown run_id=%s type=%s", event.run_id, event.type)
        return
    await q.put(event)
