"""Offline coverage for the live conformance probes.

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

from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id
from playground import conformance
from playground.conformance import LiveConfig
from tests._bodies import mock_body

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

# probe_receipts_profile_advertised asserts the receipts profile BEFORE the
# version, and _WELL_KNOWN's profiles list does not include it — every test
# below that exercises the version logic must add it.
_WELL_KNOWN_RECEIPTS = dict(
    _WELL_KNOWN, profiles=[*_WELL_KNOWN["profiles"], "acdp-registry-receipts"]
)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=_BASE)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("0.2.0", (0, 2, 0)),
        ("0.5.0", (0, 5, 0)),
        ("1.0.0", (1, 0, 0)),
        ("0.10.0", (0, 10, 0)),
        ("10.20.30", (10, 20, 30)),
        ("999999.0.0", (999999, 0, 0)),
    ],
)
def test_parse_acdp_version_accepts_well_formed(raw, expected):
    assert conformance._parse_acdp_version(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        None,
        5,
        ["0.5.0"],
        "",
        "0.5",
        "0.5.0.1",
        "v0.5.0",
        "0.05.0",
        "abc",
        " 0.5.0 ",
        "0.5.0-rc.1",
        "9999999999.0.0",
        "1000000.0.0",
    ],
)
def test_parse_acdp_version_rejects_malformed(raw):
    assert conformance._parse_acdp_version(raw) is None


def test_version_ordering_is_numeric_not_lexicographic():
    assert conformance._parse_acdp_version("0.10.0") > conformance._parse_acdp_version("0.9.0")


async def test_receipts_probe_accepts_future_spec_line():
    """The #58 regression: a spec line newer than the known set still passes,
    flagged (not failed) in the summary."""

    def handler(request: httpx.Request) -> httpx.Response:
        wk = dict(_WELL_KNOWN_RECEIPTS, acdp_version="0.6.0")
        return httpx.Response(200, json=wk)

    async with _client(handler) as client:
        summary = await conformance.probe_receipts_profile_advertised(client, _CFG)
    assert "acdp_version=0.6.0" in summary
    assert "ahead of the known set" in summary


async def test_receipts_probe_accepts_floor_exactly():
    def handler(request: httpx.Request) -> httpx.Response:
        wk = dict(_WELL_KNOWN_RECEIPTS, acdp_version="0.2.0")
        return httpx.Response(200, json=wk)

    async with _client(handler) as client:
        summary = await conformance.probe_receipts_profile_advertised(client, _CFG)
    assert "acdp_version=0.2.0" in summary
    assert "ahead of the known set" not in summary


async def test_receipts_probe_rejects_below_floor():
    def handler(request: httpx.Request) -> httpx.Response:
        wk = dict(_WELL_KNOWN_RECEIPTS, acdp_version="0.1.0")
        return httpx.Response(200, json=wk)

    async with _client(handler) as client:
        with pytest.raises(AssertionError):
            await conformance.probe_receipts_profile_advertised(client, _CFG)


@pytest.mark.parametrize("bad_version", [None, 5, "0.5"])
async def test_receipts_probe_rejects_malformed_version(bad_version):
    def handler(request: httpx.Request) -> httpx.Response:
        if bad_version is None:
            wk = {k: v for k, v in _WELL_KNOWN_RECEIPTS.items() if k != "acdp_version"}
        else:
            wk = dict(_WELL_KNOWN_RECEIPTS, acdp_version=bad_version)
        return httpx.Response(200, json=wk)

    async with _client(handler) as client:
        with pytest.raises(AssertionError):
            await conformance.probe_receipts_profile_advertised(client, _CFG)


def test_known_versions_are_all_above_floor():
    for raw in conformance._KNOWN_ACDP_VERSIONS:
        parsed = conformance._parse_acdp_version(raw)
        assert parsed is not None
        assert parsed >= conformance._MIN_ACDP_VERSION


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


async def test_receipts_probe_rejects_profiles_as_string():
    """#64: a bare-string ``profiles`` must not pass via substring matching.

    A malformed/malicious registry returning
    ``"profiles": "acdp-registry-receipts-not-really"`` would satisfy
    ``"acdp-registry-receipts" in profiles`` under Python's substring fallback
    even though that is a different, non-conformant profile name. The
    ``isinstance(profiles, list)`` guard must reject this outright.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        wk = dict(_WELL_KNOWN_RECEIPTS, profiles="acdp-registry-receipts-not-really")
        return httpx.Response(200, json=wk)

    async with _client(handler) as client:
        with pytest.raises(AssertionError, match="not a list"):
            await conformance.probe_receipts_profile_advertised(client, _CFG)


async def test_advertises_helper_rejects_profiles_as_string():
    """#64: the shared ``_advertises`` helper (used by every 0.3.0-endpoint
    probe) has the same substring-matching risk and must reject a bare-string
    ``profiles`` rather than silently matching a substring."""

    def handler(request: httpx.Request) -> httpx.Response:
        wk = dict(_WELL_KNOWN, profiles="acdp-registry-transparency-log-not-really")
        return httpx.Response(200, json=wk)

    async with _client(handler) as client:
        with pytest.raises(AssertionError, match="not a list"):
            await conformance.probe_log_checkpoint_signed(client, _CFG)


async def test_did_key_method_probe_rejects_methods_as_string():
    """#64: ``probe_did_key_method_advertised`` has the same substring-matching
    risk as the two sites above — a bare-string ``supported_did_methods`` must
    not pass via substring matching (``"did:key" in "did:key-not-really"`` is
    ``True`` under Python's string fallback even though it is a different,
    non-conformant methods list)."""

    def handler(request: httpx.Request) -> httpx.Response:
        wk = dict(_WELL_KNOWN, supported_did_methods="did:key-not-really")
        return httpx.Response(200, json=wk)

    async with _client(handler) as client:
        with pytest.raises(AssertionError, match="not a list"):
            await conformance.probe_did_key_method_advertised(client, _CFG)


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


# ── served ctx_id binding (RFC-ACDP-0006 §4.1 step 7) ───────────────────────

_BOUND_CTX = synthetic_ctx_id("registry-c.test", "conformance:ctx-binding:bound")
_BOUND_BODY = mock_body(
    authority="registry-c.test", seed="conformance:ctx-binding:bound", ctx_id=_BOUND_CTX
)
_OTHER_CTX = synthetic_ctx_id("registry-c.test", "conformance:ctx-binding:other")
_OTHER_BODY = mock_body(
    authority="registry-c.test", seed="conformance:ctx-binding:other", ctx_id=_OTHER_CTX
)


def _ctx_binding_registry(served_envelope_body: dict, served_bare_body: dict):
    """A registry that assigns ``_BOUND_CTX`` on publish and then serves
    whatever bodies the test tells it to under that id."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                201,
                json={
                    "ctx_id": _BOUND_CTX,
                    "lineage_id": _BOUND_BODY["lineage_id"],
                    "version": 1,
                    "created_at": _BOUND_BODY["created_at"],
                    "status": "active",
                },
            )
        if request.url.path.endswith("/body"):
            return httpx.Response(200, json=served_bare_body)
        return httpx.Response(
            200, json={"body": served_envelope_body, "registry_state": {"status": "active"}}
        )

    return handler


async def test_ctx_id_binding_probe_passes_on_bound_body():
    async with _client(_ctx_binding_registry(_BOUND_BODY, _BOUND_BODY)) as client:
        summary = await conformance.probe_served_ctx_id_binding(client, _CFG)
    assert _BOUND_CTX in summary


async def test_ctx_id_binding_probe_detects_drift():
    """A registry serving another valid context under the requested id must
    make the probe fail.

    This is the mock-drift counterpart of the client-side enforcement: the
    substituted body is correctly signed and hashes true, so nothing *except*
    the requested-vs-served ``ctx_id`` comparison can tell. If the probe passed
    here it would be asserting nothing.
    """
    async with _client(_ctx_binding_registry(_OTHER_BODY, _BOUND_BODY)) as client:
        with pytest.raises(AssertionError, match="context substitution"):
            await conformance.probe_served_ctx_id_binding(client, _CFG)


async def test_ctx_id_binding_probe_checks_the_bare_body_route_too():
    """The envelope may be honest while ``/contexts/{id}/body`` is not — the
    client binds both shapes, so the probe must too."""
    async with _client(_ctx_binding_registry(_BOUND_BODY, _OTHER_BODY)) as client:
        with pytest.raises(AssertionError, match=r"/body"):
            await conformance.probe_served_ctx_id_binding(client, _CFG)


def test_ctx_id_binding_probe_registered():
    assert conformance.probe_served_ctx_id_binding in conformance.REGISTRY_PROBES


# ── registry-contract probes: media type, interim revocation, anchors ───────
#
# Three externally-observable registry contracts the playground depends on and
# previously asserted nowhere. Each probe gets a drift counterpart here: a mock
# serving the *wrong* answer must make the probe raise, so the probe cannot
# quietly degrade into something that passes against any registry at all.

_PUBLISH_CTX = synthetic_ctx_id("registry-c.test", "conformance:probe-publish")
_ACCEPTED_PUBLISH = {
    "ctx_id": _PUBLISH_CTX,
    "lineage_id": synthetic_lineage_id(_PUBLISH_CTX),
    "version": 1,
    "created_at": "2026-07-05T08:40:00.000Z",
    "status": "active",
}


def _accepted() -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": conformance._ACDP_CONTENT_TYPE},
        content=json.dumps(_ACCEPTED_PUBLISH),
    )


def _envelope_response(status: int, code: str, message: str) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": conformance._ACDP_CONTENT_TYPE},
        content=json.dumps({"error": {"code": code, "message": message}}),
    )


_UNSUPPORTED_MESSAGE = "Expected request with `Content-Type: application/json`"


def _media_type_registry(*, text_plain=None, present_json=None, absent=None):
    """A registry whose ``POST /contexts`` answer is chosen by the request's
    ``Content-Type``. Each arm defaults to the conformant answer."""

    def handler(request: httpx.Request) -> httpx.Response:
        ctype = request.headers.get("content-type")
        if ctype is None:
            arm = absent
        elif ctype.split(";")[0].strip() == "application/json":
            arm = present_json
        else:
            arm = text_plain
        if arm is not None:
            return arm()
        if ctype is not None and ctype.split(";")[0].strip() != "application/json":
            return _envelope_response(415, "unsupported_media_type", _UNSUPPORTED_MESSAGE)
        return _accepted()

    return handler


async def test_media_type_probe_passes_on_conformant_mock():
    async with _client(_media_type_registry()) as client:
        summary = await conformance.probe_media_type_gate(client, _CFG)
    assert "415 unsupported_media_type" in summary
    assert "absent header accepted" in summary


async def test_media_type_probe_detects_rejection_drift():
    """The narrowing this probe exists for: a registry that stops accepting
    ``application/json`` (or stops stripping its parameters) breaks every
    publish, retract and republish the playground makes."""
    async with _client(
        _media_type_registry(
            present_json=lambda: _envelope_response(
                415, "unsupported_media_type", _UNSUPPORTED_MESSAGE
            )
        )
    ) as client:
        with pytest.raises(AssertionError, match="was NOT accepted"):
            await conformance.probe_media_type_gate(client, _CFG)


async def test_media_type_probe_detects_acceptance_drift():
    """A registry that accepts a body labelled ``text/plain`` has no §4.1 gate
    at all."""
    async with _client(_media_type_registry(text_plain=_accepted)) as client:
        with pytest.raises(AssertionError, match="expected 415"):
            await conformance.probe_media_type_gate(client, _CFG)


async def test_media_type_probe_detects_absent_header_rejection():
    """The data-plane-scoped assertion, pinned in its own right: ``POST
    /contexts`` infers a type for a header-less body. (``/auth/*`` rejects one,
    which is why this probe never generalizes the claim.)"""
    async with _client(
        _media_type_registry(
            absent=lambda: _envelope_response(415, "unsupported_media_type", _UNSUPPORTED_MESSAGE)
        )
    ) as client:
        with pytest.raises(AssertionError, match="no Content-Type was NOT accepted"):
            await conformance.probe_media_type_gate(client, _CFG)


async def test_media_type_probe_checks_the_envelope_code_not_just_the_status():
    """A 415 carrying the wrong wire code is still drift — a proxy answering
    415 on its own would otherwise be mistaken for a conformant registry."""
    async with _client(
        _media_type_registry(text_plain=lambda: _envelope_response(415, "schema_violation", "nope"))
    ) as client:
        with pytest.raises(AssertionError, match="expected code unsupported_media_type"):
            await conformance.probe_media_type_gate(client, _CFG)


_INTERIM_MESSAGE = (
    "schema violation: context_type 'acdp:key-revocation' (the interim key-revocation form) "
    "is retired for registries advertising acdp_version >= 0.5.0 (RFC-ACDP-0014 §10)"
)


def _interim_registry(*, publish=None, acdp_version="0.5.0"):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/acdp.json":
            return httpx.Response(200, json=dict(_WELL_KNOWN, acdp_version=acdp_version))
        if publish is not None:
            return publish()
        return _envelope_response(400, "schema_violation", _INTERIM_MESSAGE)

    return handler


async def test_interim_revocation_probe_passes_on_conformant_mock():
    async with _client(_interim_registry()) as client:
        summary = await conformance.probe_interim_revocation_type_rejected(client, _CFG)
    assert "400 schema_violation" in summary


async def test_interim_revocation_probe_detects_acceptance():
    """A registry that still accepts the retired interim form must fail the
    probe, not skip it — S32 publishes the modern spelling and would never
    notice the regression on its own."""
    async with _client(_interim_registry(publish=_accepted)) as client:
        with pytest.raises(AssertionError, match="never retired it"):
            await conformance.probe_interim_revocation_type_rejected(client, _CFG)


async def test_interim_revocation_probe_rejects_an_unrelated_schema_violation():
    """``schema_violation`` is the registry's generic body-rejection code. A
    400 that does not name the retired type could be any defect at all, and
    would let the probe pass against a registry with no §10 gate."""
    async with _client(
        _interim_registry(
            publish=lambda: _envelope_response(
                400, "schema_violation", "schema violation: content_hash mismatch"
            )
        )
    ) as client:
        with pytest.raises(AssertionError, match="does not name the retired context type"):
            await conformance.probe_interim_revocation_type_rejected(client, _CFG)


async def test_interim_revocation_probe_skips_below_0_5_0():
    """Below 0.5.0 §10 requires a registry to treat the interim form as an
    ordinary opaque custom type and accept it, so a rejection there would be
    the non-conformant answer. Documented skip, and the publish never happens."""
    async with _client(_interim_registry(publish=_accepted, acdp_version="0.4.0")) as client:
        summary = await conformance.probe_interim_revocation_type_rejected(client, _CFG)
    assert "skipped" in summary


_ANCHORS_MESSAGE = (
    "schema violation: anchors requires the publish request to declare acdp_version >= 0.5.0 "
    "(RFC-ACDP-0016 §14); this request declared '0.4.0'"
)


def _anchors_registry(publish=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if publish is not None:
            return publish()
        return _envelope_response(400, "schema_violation", _ANCHORS_MESSAGE)

    return handler


async def test_anchors_version_gate_probe_passes_on_conformant_mock():
    async with _client(_anchors_registry()) as client:
        summary = await conformance.probe_anchors_require_0_5_0(client, _CFG)
    assert "400 schema_violation" in summary


async def test_anchors_version_gate_probe_detects_drift():
    """S33 depends on this gate being real; a registry that admits anchors
    under a sub-0.5.0 declared version must fail the probe."""
    async with _client(_anchors_registry(publish=_accepted)) as client:
        with pytest.raises(AssertionError, match="no §14 gate"):
            await conformance.probe_anchors_require_0_5_0(client, _CFG)


async def test_anchors_version_gate_probe_rejects_an_unrelated_schema_violation():
    async with _client(
        _anchors_registry(
            publish=lambda: _envelope_response(
                400, "schema_violation", "schema violation: content_hash mismatch"
            )
        )
    ) as client:
        with pytest.raises(AssertionError, match="names neither anchors"):
            await conformance.probe_anchors_require_0_5_0(client, _CFG)


def test_registry_contract_probes_registered():
    for probe in (
        conformance.probe_media_type_gate,
        conformance.probe_interim_revocation_type_rejected,
        conformance.probe_anchors_require_0_5_0,
    ):
        assert probe in conformance.REGISTRY_PROBES, probe.__name__
