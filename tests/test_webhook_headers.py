"""The webhook receiver lifts tenant + dedup id from headers onto the
event and the SSE step (they ride out-of-band, never in the signed body)."""

from __future__ import annotations

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id
from playground.config import get_settings
from playground.events import create_queue, drop_queue
from playground.main import app

# Webhook deliveries carry the ids a registry would have assigned, so the
# fixtures mint conformant ones rather than the ``/c1`` placeholders they
# used to hand-write.
_CTX_A = synthetic_ctx_id("registry-a.playground.local", "webhook-publish")
_CTX_A2 = synthetic_ctx_id("registry-a.playground.local", "webhook-search")
_CTX_C = synthetic_ctx_id("registry-c.playground.local", "webhook-receipt")
_CTX_A_LIFECYCLE = synthetic_ctx_id("registry-a.playground.local", "webhook-lifecycle")
_LINEAGE_A_LIFECYCLE = synthetic_lineage_id("webhook-lifecycle")


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhook_lifts_tenant_and_event_id_to_sse():
    settings = get_settings()
    secret = settings.webhook_secret
    run_id = "run-webhook-test"
    queue = create_queue(run_id)
    try:
        body = json.dumps(
            {
                "type": "context_published",
                "agent_id": "did:web:registry-a.playground.local:agents:x",
                "ctx_id": _CTX_A,
                "run_id": run_id,
            }
        ).encode()
        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/acdp",
                content=body,
                headers={
                    "X-ACDP-Signature": _sign(secret, body),
                    "X-Tenant-Id": "tenant-a",
                    "X-ACDP-Event-Id": "evt-77",
                    "Content-Type": "application/json",
                },
            )
        assert resp.status_code == 204
        # The SSE queue received a step carrying the lifted metadata.
        step = queue.get_nowait()
        assert step.tenant_id == "tenant-a"
        assert step.event_id == "evt-77"
        assert step.type == "acdp.publish"
    finally:
        drop_queue(run_id)


def test_webhook_lifts_receipt_trust_signals_to_sse():
    """A publish webhook carrying a registry receipt + key_fingerprint streams
    them as top-level StepEvent fields so a live run renders the receipt chip
    (RFC-ACDP-0010), matching what the control plane hydrates for past runs."""
    settings = get_settings()
    secret = settings.webhook_secret
    run_id = "run-webhook-receipt"
    fp = "sha256:" + "ab" * 32
    queue = create_queue(run_id)
    try:
        body = json.dumps(
            {
                "type": "context_published",
                "agent_id": "did:key:z6Mkxyz",
                "ctx_id": _CTX_C,
                "run_id": run_id,
                "key_fingerprint": fp,
                "registry_receipt": {"ctx_id": _CTX_C},
            }
        ).encode()
        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/acdp",
                content=body,
                headers={
                    "X-ACDP-Signature": _sign(secret, body),
                    "Content-Type": "application/json",
                },
            )
        assert resp.status_code == 204
        step = queue.get_nowait()
        assert step.type == "acdp.publish"
        assert step.key_fingerprint == fp
        assert step.receipt_present is True
    finally:
        drop_queue(run_id)


def test_webhook_retrieve_leaves_receipt_present_unset():
    """receipt_present is a publish-time signal (mirrors the control plane); a
    retrieve webhook leaves it null rather than asserting a false negative."""
    settings = get_settings()
    secret = settings.webhook_secret
    run_id = "run-webhook-retrieve"
    queue = create_queue(run_id)
    try:
        body = json.dumps(
            {
                "type": "context_retrieved",
                "ctx_id": _CTX_C,
                "run_id": run_id,
                "key_fingerprint": "sha256:" + "cd" * 32,
            }
        ).encode()
        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/acdp",
                content=body,
                headers={
                    "X-ACDP-Signature": _sign(secret, body),
                    "Content-Type": "application/json",
                },
            )
        assert resp.status_code == 204
        step = queue.get_nowait()
        assert step.type == "acdp.retrieve"
        assert step.key_fingerprint == "sha256:" + "cd" * 32
        assert step.receipt_present is None
    finally:
        drop_queue(run_id)


def test_webhook_run_id_from_header_when_absent_in_body():
    settings = get_settings()
    secret = settings.webhook_secret
    run_id = "run-from-header"
    queue = create_queue(run_id)
    try:
        body = json.dumps(
            {
                "type": "search_executed",
                "ctx_id": _CTX_A2,
            }
        ).encode()
        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/acdp",
                content=body,
                headers={
                    "X-ACDP-Signature": _sign(secret, body),
                    "X-Run-Id": run_id,
                    "Content-Type": "application/json",
                },
            )
        assert resp.status_code == 204
        step = queue.get_nowait()
        assert step.type == "acdp.search"
    finally:
        drop_queue(run_id)


# ── RFC-ACDP-0013 lifecycle deliveries (playground#71) ───────────────────────
#
# These two bodies are the documented acdp-registry-rs deliveries, copied from
# its ``docs/WEBHOOKS.md``, and are paired with the **dotted** ``X-ACDP-Event``
# header the registry actually sends. That split is the point of the fixtures:
# the registry derives the body's ``type`` from
# ``#[serde(tag = "type", rename_all = "snake_case")]`` (underscores) while the
# header carries ``event.name()`` (dots), and its own test pins them as
# deliberately different wire contracts. A fixture that used the dotted form in
# the body would be asserting against a contract the registry never emits.

_RETRACTED = {
    "event_id": "e0f5-envelope-delivery-id",
    "schema_version": "1.0",
    "type": "context_retracted",
    "registry_authority": "registry-a.playground.local",
    "ctx_id": _CTX_A_LIFECYCLE,
    "lineage_id": _LINEAGE_A_LIFECYCLE,
    "actor": "did:web:registry-a.playground.local:agents:producer",
    "lifecycle_event_id": "0195a1c2-0000-7000-8000-000000000001",
    "reason": "superseded by a newer context",
    "at": "2026-06-10T12:03:00Z",
}

# `reason` is omitted entirely when absent — never null.
_REPUBLISHED = {
    "event_id": "e0f2-envelope-delivery-id",
    "schema_version": "1.0",
    "type": "context_republished",
    "registry_authority": "registry-a.playground.local",
    "ctx_id": _CTX_A_LIFECYCLE,
    "lineage_id": _LINEAGE_A_LIFECYCLE,
    "actor": "did:web:registry-a.playground.local:agents:producer",
    "lifecycle_event_id": "0195a1c3-0000-7000-8000-000000000002",
    "at": "2026-06-10T12:04:00Z",
}


def _post_delivery(payload: dict, dotted_event: str, run_id: str):
    """POST one registry-shaped delivery and return the queued SSE step."""
    secret = get_settings().webhook_secret
    body = json.dumps(dict(payload, run_id=run_id)).encode()
    with TestClient(app) as client:
        resp = client.post(
            "/webhooks/acdp",
            content=body,
            headers={
                "X-ACDP-Signature": _sign(secret, body),
                # Dotted in the header, underscored in the body — as emitted.
                "X-ACDP-Event": dotted_event,
                "X-ACDP-Event-Id": payload["event_id"],
                "Content-Type": "application/json",
            },
        )
    assert resp.status_code == 204
    return resp


def test_retracted_delivery_reaches_the_sse_stream():
    run_id = "run-lifecycle-retract"
    queue = create_queue(run_id)
    try:
        _post_delivery(_RETRACTED, "context.retracted", run_id)
        step = queue.get_nowait()
        assert step.type == "acdp.retract"
        assert step.ctx_id == _RETRACTED["ctx_id"]
        assert step.title == "Context retracted"
        assert step.preview == "superseded by a newer context"
    finally:
        drop_queue(run_id)


def test_republished_delivery_reaches_the_sse_stream():
    run_id = "run-lifecycle-republish"
    queue = create_queue(run_id)
    try:
        _post_delivery(_REPUBLISHED, "context.republished", run_id)
        step = queue.get_nowait()
        assert step.type == "acdp.republish"
        assert step.title == "Context republished"
        # `reason` was omitted, not null.
        assert step.preview is None
    finally:
        drop_queue(run_id)


def test_lifecycle_dedup_uses_the_envelope_id_not_the_actor_minted_one():
    """acdp-registry-rs#179: the actor-minted id is `lifecycle_event_id` and the
    envelope's `event_id` (== X-ACDP-Event-Id) stays the per-delivery dedupe key.
    Deduping on the actor-minted id would re-create the bug #179 fixed — a
    retract redelivered under a new envelope id would be collapsed away."""
    run_id = "run-lifecycle-dedup"
    queue = create_queue(run_id)
    try:
        _post_delivery(_RETRACTED, "context.retracted", run_id)
        step = queue.get_nowait()
        assert step.event_id == _RETRACTED["event_id"]
        assert step.event_id != _RETRACTED["lifecycle_event_id"]
    finally:
        drop_queue(run_id)


def test_registry_body_type_is_underscored_for_every_emitted_event():
    """The five values acdp-registry-rs serialises into the body's `type`. If
    the registry ever switched the body to the dotted header form, this fails
    loudly here rather than silently dropping every delivery at validation."""
    from acdp_client.models import StepEvent, WebhookEvent

    expected = {
        "context_published": "acdp.publish",
        "context_retrieved": "acdp.retrieve",
        "context_retracted": "acdp.retract",
        "context_republished": "acdp.republish",
        "search_executed": "acdp.search",
    }
    for wire_type, step_type in expected.items():
        event = WebhookEvent.model_validate({"type": wire_type})
        assert StepEvent.from_webhook("r", "t", event).type == step_type
