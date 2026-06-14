"""The webhook receiver lifts tenant + dedup id from headers onto the
event and the SSE step (they ride out-of-band, never in the signed body)."""

from __future__ import annotations

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from playground.config import get_settings
from playground.events import create_queue, drop_queue
from playground.main import app


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
                "ctx_id": "acdp://registry-a.playground.local/c1",
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
                "ctx_id": "acdp://registry-c.playground.local/c9",
                "run_id": run_id,
                "key_fingerprint": fp,
                "registry_receipt": {"ctx_id": "acdp://registry-c.playground.local/c9"},
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
                "ctx_id": "acdp://registry-c.playground.local/c9",
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
                "ctx_id": "acdp://registry-a.playground.local/c2",
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
