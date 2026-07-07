"""Offline coverage for the live 0.3.0-endpoint conformance probes.

The probes' *purpose* is mock-drift detection against the real binaries, so they
are normally gated behind ``ACDP_LIVE_STACK``. These tests exercise the probe
*logic* offline with ``httpx.MockTransport``: a probe passes against a
conformant response shape and **raises** against a drifted one — the exact
signal it would emit against a real registry that regressed. This keeps the
contract encoded in the probe honest without a running stack.
"""

from __future__ import annotations

import json

import httpx
import pytest

from playground import conformance
from playground.conformance import LiveConfig

_BASE = "http://registry-c.test"

_CFG = LiveConfig(
    registry_url=_BASE,
    receipts_registry_url=_BASE,
    control_plane_url="http://cp.test",
    admin_token="t",
    api_key="t",
)

_WELL_KNOWN = {
    "acdp_version": "0.3.0",
    "profiles": [
        "acdp-registry-core",
        "acdp-registry-transparency-log",
        "acdp-registry-head-receipts",
        "acdp-registry-lifecycle",
    ],
    "supported_did_methods": ["did:web", "did:key"],
}

_CHECKPOINT = {
    "checkpoint_version": "acdp-log/1",
    "log_id": f"did:web:{_BASE}/log/1",
    "tree_size": 3,
    "root_hash": "sha256:" + "ab" * 32,
    "timestamp": "2026-07-05T08:40:00.000Z",
    "signature": {"algorithm": "ed25519", "key_id": "did:web:reg#receipt-key-1", "value": "AA"},
}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=_BASE)


def test_version_set_accepts_0_4_0():
    assert "0.4.0" in conformance._ACCEPTED_ACDP_VERSIONS
    assert {"0.2.0", "0.3.0"} <= conformance._ACCEPTED_ACDP_VERSIONS


def test_new_0_3_0_probes_registered():
    names = {p.__name__ for p in conformance.ALL_PROBES}
    assert {
        "probe_log_checkpoint_signed",
        "probe_log_proof_inclusion_and_consistency",
        "probe_head_receipt_on_current",
        "probe_retract_endpoint_fails_closed",
    } <= names
    assert conformance.ENDPOINT_0_3_0_PROBES  # ordered group exposed for smoke --live


async def test_log_checkpoint_probe_passes_on_conformant_mock():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/acdp.json":
            return httpx.Response(200, json=_WELL_KNOWN)
        if request.url.path == "/log/checkpoint":
            return httpx.Response(200, json=_CHECKPOINT)
        return httpx.Response(404)

    async with _client(handler) as client:
        summary = await conformance.probe_log_checkpoint_signed(client, _CFG)
    assert "acdp-log/1" in summary


async def test_log_checkpoint_probe_fails_on_drift():
    """A drifted checkpoint_version is exactly the mock-vs-real gap the probe
    exists to catch."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/acdp.json":
            return httpx.Response(200, json=_WELL_KNOWN)
        drifted = dict(_CHECKPOINT, checkpoint_version="acdp-log/2")
        return httpx.Response(200, json=drifted)

    async with _client(handler) as client:
        with pytest.raises(AssertionError):
            await conformance.probe_log_checkpoint_signed(client, _CFG)


async def test_log_checkpoint_probe_skips_when_profile_absent():
    """A legitimately-0.2.0 registry (no transparency-log profile) is a
    documented skip, not a failure."""

    def handler(request: httpx.Request) -> httpx.Response:
        wk = dict(_WELL_KNOWN, acdp_version="0.2.0", profiles=["acdp-registry-core"])
        return httpx.Response(200, json=wk)

    async with _client(handler) as client:
        summary = await conformance.probe_log_checkpoint_signed(client, _CFG)
    assert "skipped" in summary


async def test_retract_probe_fails_when_endpoint_accepts_unauthorized():
    """A registry (or mock) that stubs retract as an unconditional 2xx must be
    caught — the probe's core assertion."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/acdp.json":
            return httpx.Response(200, json=_WELL_KNOWN)
        # Wrongly accepts the unauthorized retract.
        return httpx.Response(200, json={"body": {}, "registry_state": {"status": "retracted"}})

    async with _client(handler) as client:
        with pytest.raises(AssertionError):
            await conformance.probe_retract_endpoint_fails_closed(client, _CFG)


async def test_retract_probe_passes_on_conformant_envelope():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/acdp.json":
            return httpx.Response(200, json=_WELL_KNOWN)
        return httpx.Response(
            404,
            headers={"content-type": "application/acdp+json"},
            content=json.dumps({"error": {"code": "not_found", "message": "context not found"}}),
        )

    async with _client(handler) as client:
        summary = await conformance.probe_retract_endpoint_fails_closed(client, _CFG)
    assert "not_found" in summary
