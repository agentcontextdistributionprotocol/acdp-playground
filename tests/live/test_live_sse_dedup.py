"""SSE de-duplication — CP #51 stretch check.

CP #51 fixed a Redis StreamHub bug where a same-instance SSE subscriber received
every event twice (the local Subject and the subscriber round-trip both
delivered). The fix makes the round-trip the single delivery path.

This bug **only reproduces against the Redis StreamHub strategy**. The demo
``docker-compose.full.yml`` runs ``STREAM_HUB_STRATEGY=memory``, which never
double-delivered, so this test is gated behind its own ``ACDP_LIVE_SSE`` flag
(in addition to ``ACDP_LIVE_STACK``) — enable it only against a Redis-backed
stack. It is best-effort: it subscribes to ``GET /events/stream``, drives a few
distinct ingest events through the bridge, and asserts no event id is delivered
to the subscriber more than once.
"""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest

from playground.conformance import LiveConfig
from playground.config import Settings
from playground.control_plane import ControlPlaneClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("ACDP_LIVE_SSE"),
    reason="SSE de-dup only reproduces on a Redis StreamHub — set ACDP_LIVE_SSE=1",
)

_N_EVENTS = 3
_COLLECT_SECONDS = 4.0


async def _collect_event_ids(
    client: httpx.AsyncClient, url: str, token: str, seen: list[str]
) -> None:
    headers = {"Authorization": f"Bearer {token}", "Accept": "text/event-stream"}
    async with client.stream("GET", url, headers=headers) as resp:
        resp.raise_for_status()
        async for line in resp.aiter_lines():
            # SSE frames: an `id:` line carries the per-event delivery id.
            if line.startswith("id:"):
                seen.append(line[len("id:") :].strip())


async def test_sse_no_duplicate_delivery(live_config: LiveConfig):
    cfg = live_config
    seen: list[str] = []
    async with httpx.AsyncClient(timeout=_COLLECT_SECONDS + 2) as client:
        url = f"{cfg.control_plane_url}/events/stream"
        collector = asyncio.create_task(_collect_event_ids(client, url, cfg.admin_token, seen))
        # Let the subscription establish before producing events.
        await asyncio.sleep(0.5)

        cp = ControlPlaneClient(
            Settings(
                control_plane_url=cfg.control_plane_url,
                control_plane_hmac_secret=os.environ.get(
                    "CONTROL_PLANE_HMAC_SECRET", "playground-cp-secret"
                ),
                control_plane_admin_token=cfg.admin_token,
            )
        )
        try:
            for i in range(_N_EVENTS):
                await cp.forward_webhook(
                    b'{"type":"context_published","probe":%d}' % i,
                    headers={
                        "X-ACDP-Event": "context_published",
                        "X-ACDP-Event-Id": f"sse-dedup-probe-{i}",
                    },
                )
            await asyncio.sleep(_COLLECT_SECONDS)
        finally:
            await cp.aclose()
            collector.cancel()
            try:
                await collector
            except (asyncio.CancelledError, httpx.HTTPError):
                pass

    duplicates = {eid for eid in seen if seen.count(eid) > 1}
    assert not duplicates, f"SSE delivered duplicate event ids: {sorted(duplicates)}"
