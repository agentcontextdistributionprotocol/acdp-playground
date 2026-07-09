"""POST /webhooks/acdp — receive webhooks from registries, fan into SSE,
optionally forward to control plane.

Signature header: ``X-ACDP-Signature: sha256=<hex>`` (GitHub-style).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status

from acdp_client.models import WebhookEvent, StepEvent
from playground.config import get_settings
from playground.control_plane import get_control_plane
from playground.events import get_queue

log = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _verify(secret: str, body: bytes, header: str | None) -> None:
    if not secret:
        return
    if not header:
        raise HTTPException(401, "missing X-ACDP-Signature")
    if not header.startswith("sha256="):
        raise HTTPException(401, "unsupported signature algorithm")
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, header[len("sha256=") :]):
        raise HTTPException(401, "invalid signature")


@router.post("/acdp", status_code=status.HTTP_204_NO_CONTENT)
async def receive_acdp_webhook(request: Request):
    settings = get_settings()
    body = await request.body()
    _verify(settings.webhook_secret, body, request.headers.get("x-acdp-signature"))

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "invalid JSON") from None

    try:
        event = WebhookEvent.model_validate(payload)
    except Exception as e:  # noqa: BLE001 — never fatal
        log.warning("webhook payload didn't match WebhookEvent: %s payload=%s", e, payload)
        return

    # Tenant + dedup id ride in the headers, not the signed body
    # (RFC-ACDP-0008 §6.4). Lift them onto the event so the SSE stream
    # and downstream forward see them.
    headers = request.headers
    if event.tenant_id is None:
        event.tenant_id = headers.get("x-tenant-id")
    if event.event_id is None:
        event.event_id = headers.get("x-acdp-event-id")
    if event.run_id is None:
        event.run_id = headers.get("x-run-id")

    # Fan into the SSE queue if the run is live.
    if event.run_id:
        queue = get_queue(event.run_id)
        if queue is not None:
            step = StepEvent.from_webhook(
                event.run_id, datetime.now(timezone.utc).isoformat(), event
            )
            await queue.put(step)

    # Forward to control plane (no-op when CONTROL_PLANE_URL unset).
    cp = get_control_plane(settings)
    import asyncio

    asyncio.create_task(cp.forward_webhook(body, dict(request.headers), tenant_id=event.tenant_id))
