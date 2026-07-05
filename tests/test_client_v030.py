"""AcdpClient ACDP 0.3.0 surface: lifecycle endpoints, /log/*, head receipts.

MockTransport tests pinning the request shapes the client emits (the closed
``{"event": …}`` lifecycle envelope, byte-verbatim event splicing, the
``/log/proof`` query modes) and the typed error mapping for the three new
wire codes (``immutable_field`` / ``invalid_lifecycle_transition`` /
``invalid_log_proof``). The registry-side contracts these mirror live in
acdp-registry-rs (HTTP-API.md) — the live suite re-validates them against
the real binary.
"""

from __future__ import annotations

import json
from urllib.parse import quote

import httpx
import pytest

from acdp_client import (
    AcdpClient,
    AcdpHTTPError,
    ImmutableFieldError,
    InvalidLifecycleTransitionError,
    InvalidLogProofError,
)
from acdp_client.models import FullContext, RegistryState

CTX = "acdp://reg.test/12345678-1234-4321-8123-123456781234"

_BODY = {
    "ctx_id": CTX,
    "lineage_id": "lin:sha256:" + "ab" * 32,
    "origin_registry": "reg.test",
    "created_at": "2026-07-05T09:00:00.000Z",
    "content_hash": "sha256:" + "cd" * 32,
    "signature": {"algorithm": "ed25519", "key_id": "did:key:z6Mk#z6Mk", "value": "AA=="},
    "version": 1,
    "agent_id": "did:key:z6Mk",
    "title": "t",
    "type": "data_snapshot",
    "visibility": "public",
}

_EVENT = {
    "event_id": "018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f",
    "ctx_id": CTX,
    "event_type": "retracted",
    "occurred_at": "2026-07-05T09:15:42.000Z",
    "actor": "did:key:z6Mk",
    "signature": {"algorithm": "ed25519", "key_id": "did:key:z6Mk#z6Mk", "value": "AA=="},
}


def _client(handler, **kwargs) -> AcdpClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://reg.test")
    return AcdpClient("http://reg.test", http=http, **kwargs)


def _full_context(status: str, *, events: list | None = None, head_receipt: dict | None = None):
    out = {"body": _BODY, "registry_state": {"status": status}}
    if events is not None:
        out["registry_state"]["lifecycle_events"] = events
    if head_receipt is not None:
        out["lineage_head_receipt"] = head_receipt
    return out


# ── lifecycle endpoints ──────────────────────────────────────────────────


async def test_retract_posts_closed_event_envelope_verbatim():
    """The request body is ``{"event": <event>}`` with the caller's signed
    event spliced in byte-verbatim (never re-serialized)."""
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        # raw_path preserves the percent-encoding the client actually sent
        # (url.path is decoded by httpx).
        seen["path"] = request.url.raw_path.decode()
        seen["raw"] = request.content.decode()
        return httpx.Response(200, json=_full_context("retracted", events=[_EVENT]))

    client = _client(handler)
    event_json = json.dumps(_EVENT)
    full = await client.retract(CTX, event_json)

    assert seen["path"] == f"/contexts/{quote(CTX, safe='')}/retract"
    # Closed envelope, exactly one member, event bytes verbatim.
    assert seen["raw"] == '{"event":' + event_json + "}"
    assert full.registry_state.status == "retracted"
    assert full.is_retracted and full.registry_state.is_retracted
    assert full.registry_state.lifecycle_events == [_EVENT]


async def test_republish_posts_to_republish_and_reports_active():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/republish")
        return httpx.Response(
            200,
            json=_full_context(
                "active",
                events=[_EVENT, dict(_EVENT, event_type="republished")],
            ),
        )

    client = _client(handler)
    full = await client.republish(CTX, json.dumps(dict(_EVENT, event_type="republished")))
    assert full.registry_state.status == "active"
    assert not full.is_retracted
    assert len(full.registry_state.lifecycle_events) == 2


async def test_lifecycle_events_absent_parses_as_none():
    """Lifecycle-advertising registries omit the member entirely when empty
    (never ``[]``/``null``); the model mirrors absence as None."""
    state = RegistryState.model_validate({"status": "active"})
    assert state.lifecycle_events is None
    assert state.is_retracted is False


# ── typed error mapping (RFC-ACDP-0012/0013 wire codes) ──────────────────


@pytest.mark.parametrize(
    ("status", "code", "exc"),
    [
        (400, "immutable_field", ImmutableFieldError),
        (409, "invalid_lifecycle_transition", InvalidLifecycleTransitionError),
        (502, "invalid_log_proof", InvalidLogProofError),
    ],
)
async def test_new_wire_codes_map_to_typed_exceptions(status, code, exc):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": "nope"}})

    client = _client(handler)
    with pytest.raises(exc) as ei:
        await client.retract(CTX, json.dumps(_EVENT))
    assert ei.value.status == status
    assert ei.value.code == code
    assert isinstance(ei.value, AcdpHTTPError)


# ── /log/* ───────────────────────────────────────────────────────────────


async def test_log_checkpoint_returns_verbatim_dict():
    checkpoint = {
        "checkpoint_version": "acdp-log/1",
        "log_id": "did:web:reg.test/log/1",
        "tree_size": 5,
        "root_hash": "sha256:" + "0b" * 32,
        "timestamp": "2026-07-05T12:00:00.000Z",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "did:web:reg.test#receipt-key-1",
            "value": "AA==",
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/log/checkpoint"
        return httpx.Response(200, json=checkpoint)

    client = _client(handler)
    assert await client.log_checkpoint() == checkpoint


async def test_log_proof_inclusion_mode_params():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/log/proof"
        assert request.url.params["ctx_id"] == CTX
        assert "first" not in request.url.params
        return httpx.Response(
            200,
            json={"log_id": "l", "leaf_index": 0, "tree_size": 1, "inclusion_path": []},
        )

    client = _client(handler)
    proof = await client.log_proof(ctx_id=CTX)
    assert proof["inclusion_path"] == []


async def test_log_proof_consistency_mode_params():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["first"] == "1"
        assert request.url.params["second"] == "2"
        assert "ctx_id" not in request.url.params
        return httpx.Response(
            200,
            json={
                "log_id": "l",
                "first_tree_size": 1,
                "second_tree_size": 2,
                "consistency_path": ["sha256:" + "aa" * 32],
            },
        )

    client = _client(handler)
    proof = await client.log_proof(first=1, second=2)
    assert proof["second_tree_size"] == 2


async def test_log_proof_auditor_surface_leaf_index_and_tree_size():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["leaf_index"] == "3"
        assert request.url.params["tree_size"] == "5"
        return httpx.Response(
            200,
            json={"log_id": "l", "leaf_index": 3, "tree_size": 5, "inclusion_path": []},
        )

    client = _client(handler)
    proof = await client.log_proof(leaf_index=3, tree_size=5)
    assert proof["leaf_index"] == 3


async def test_log_entries_paging_params():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/log/entries"
        assert request.url.params["start"] == "0"
        assert request.url.params["end"] == "2"
        return httpx.Response(
            200,
            json={
                "log_id": "l",
                "start": 0,
                "entries": [
                    {"leaf_index": 0, "leaf_hash": "sha256:" + "aa" * 32},
                    {"leaf_index": 1, "leaf_hash": "sha256:" + "bb" * 32},
                ],
            },
        )

    client = _client(handler)
    page = await client.log_entries(0, 2)
    assert len(page["entries"]) == 2


async def test_log_disabled_501_not_implemented():
    """A registry without a log answers 501 not_implemented — surfaced as
    the base typed error, not a lifecycle/log-specific one."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(501, json={"error": {"code": "not_implemented", "message": "no log"}})

    client = _client(handler)
    with pytest.raises(AcdpHTTPError) as ei:
        await client.log_checkpoint()
    assert ei.value.status == 501
    assert ei.value.code == "not_implemented"


# ── lineage-head receipt on /current ─────────────────────────────────────


async def test_current_surfaces_lineage_head_receipt():
    receipt = {
        "receipt_version": "acdp-lhr/1",
        "registry_did": "did:web:reg.test",
        "lineage_id": _BODY["lineage_id"],
        "head_ctx_id": CTX,
        "head_version": 1,
        "head_status": "active",
        "as_of": "2026-07-05T09:00:00.000Z",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "did:web:reg.test#receipt-key-1",
            "value": "AA==",
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_full_context("active", head_receipt=receipt))

    client = _client(handler)
    full = await client.current(_BODY["lineage_id"])
    # Typed surface (not just extra=allow), verbatim dict for the verifier.
    assert full.lineage_head_receipt == receipt
    assert FullContext.model_fields["lineage_head_receipt"] is not None


async def test_current_without_receipt_parses_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_full_context("active"))

    client = _client(handler)
    full = await client.current(_BODY["lineage_id"])
    assert full.lineage_head_receipt is None
