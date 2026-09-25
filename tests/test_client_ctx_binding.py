"""RFC-ACDP-0006 §4.1 step 7 — the served-``ctx_id`` binding, at the transport.

``ctx_id`` is assigned by the registry *after* the producer signs, so it is
covered by neither ``content_hash`` nor the producer signature (RFC-ACDP-0001
§5.7, ``acdp-rs/crates/acdp-verify/src/lib.rs:139-144``). On the receipt-less
retrieval path — which is what most scenarios use — comparing the served
``body.ctx_id`` against the requested one is therefore the *only* thing
standing between "the context I asked for" and "any other validly-signed body
from the same producer". Every other check a consumer runs still passes on a
substituted body.

These tests pin that the check runs on **every** retrieval method (the reason
:meth:`AcdpClient._get_full_context` exists at all), that its three failure
reasons stay distinguishable, and — separately — that collapsing four parallel
method bodies into one chokepoint did not cost ``retrieve_raw`` its
byte-exactness, which ``build_supersede_request`` depends on.
"""

from __future__ import annotations

import json

import httpx
import pytest

from acdp_client import AcdpClient, CtxIdBindingError
from acdp_client.identifiers import synthetic_ctx_id
from tests._bodies import mock_body

_AUTHORITY = "reg.test"
_BASE = "http://reg.test"

#: The context the caller asks for, and the body honestly bound to it.
CTX = synthetic_ctx_id(_AUTHORITY, "ctx-binding:requested")
BODY = mock_body(authority=_AUTHORITY, seed="ctx-binding:requested", ctx_id=CTX)

#: A *different* context, published by the same producer and just as valid —
#: the substitution a registry can perform today without breaking any
#: signature. Its ``ctx_id`` is its own, which is the whole tell.
OTHER_CTX = synthetic_ctx_id(_AUTHORITY, "ctx-binding:substituted")
SUBSTITUTED_BODY = mock_body(
    authority=_AUTHORITY,
    seed="ctx-binding:substituted",
    title="a perfectly valid other context",
    ctx_id=OTHER_CTX,
)

LINEAGE = BODY["lineage_id"]

#: A ctx_id ``CtxId::parse`` refuses (uppercase authority). Reuses one of the
#: repo's registered negative fixtures rather than minting a new malformed
#: literal — see ``INTENTIONALLY_MALFORMED`` in ``tests/test_identifiers.py``.
_MALFORMED_CTX = "acdp://Registry-A.Playground.Local/00000000-0000-4000-8000-000000000000"


def _envelope(body: dict) -> dict:
    return {"body": body, "registry_state": {"status": "active"}}


def _client(handler, **kwargs) -> AcdpClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=_BASE)
    return AcdpClient(_BASE, http=http, **kwargs)


def _serving(payload, *, bare_body: dict | None = None):
    """A registry that answers every read with ``payload``.

    ``bare_body`` overrides the ``/contexts/{id}/body`` route, which serves the
    body object with no envelope around it.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if bare_body is not None and request.url.path.endswith("/body"):
            return httpx.Response(200, json=bare_body)
        return httpx.Response(200, json=payload)

    return handler


# ── the four context routes, each bound ───────────────────────────────────

#: Every method that returns a served body, with the coroutine factory that
#: drives it. ``retract``/``republish`` go through ``_lifecycle``, which POSTs
#: rather than GETs and therefore had its own copy of the send/retry/raise
#: logic before the extraction.
_RETRIEVALS = {
    "retrieve": lambda c: c.retrieve(CTX),
    "retrieve_raw": lambda c: c.retrieve_raw(CTX),
    "retrieve_body": lambda c: c.retrieve_body(CTX),
    "lifecycle_retract": lambda c: c.retract(CTX, json.dumps({"event_type": "retracted"})),
}


@pytest.mark.parametrize("method", sorted(_RETRIEVALS))
async def test_every_retrieval_method_is_bound(method: str):
    """No retrieval method may be an unchecked path.

    ``retrieve`` is the most-travelled of the four (the generic consume path in
    ``playground/agents/base.py`` and ``playground/api/contexts.py`` both use
    it), so enforcing only in ``retrieve_raw`` would leave the busiest route
    unchecked while claiming universal coverage.
    """
    client = _client(
        _serving(_envelope(SUBSTITUTED_BODY), bare_body=SUBSTITUTED_BODY),
    )
    with pytest.raises(CtxIdBindingError) as exc:
        await _RETRIEVALS[method](client)
    assert exc.value.reason == "mismatch", method
    assert exc.value.requested_ctx_id == CTX
    assert exc.value.served_ctx_id == OTHER_CTX


async def test_mismatched_served_ctx_id_raises():
    """The core case: a valid body served under someone else's id."""
    client = _client(_serving(_envelope(SUBSTITUTED_BODY)))
    with pytest.raises(CtxIdBindingError) as exc:
        await client.retrieve(CTX)
    assert exc.value.reason == "mismatch"
    # The message names both halves, so a failed run is diagnosable without
    # re-running it under a debugger.
    assert CTX in str(exc.value)
    assert OTHER_CTX in str(exc.value)


async def test_matching_served_ctx_id_passes():
    """Positive control — the guard above is not passing for free."""
    client = _client(_serving(_envelope(BODY), bare_body=BODY))
    full = await client.retrieve(CTX)
    assert full.body.ctx_id == CTX
    assert (await client.retrieve_body(CTX)).ctx_id == CTX


async def test_malformed_served_ctx_id_raises_with_reason_malformed():
    """A non-conformant served id is a schema violation, not a mismatch.

    ``verify_ctx_id_binding`` runs ``CtxId::parse`` over *both* sides before
    comparing them (``acdp-rs/crates/acdp-verify/src/lib.rs:444-454``), so the
    SDK raises ``ValueError`` here rather than ``RuntimeError``. Keeping the
    two apart is what tells an operator whether the registry lied or is merely
    broken.
    """
    broken = dict(BODY, ctx_id="ctx-42")
    client = _client(_serving(_envelope(broken)))
    with pytest.raises(CtxIdBindingError) as exc:
        await client.retrieve(CTX)
    assert exc.value.reason == "malformed"
    assert exc.value.served_ctx_id == "ctx-42"


async def test_malformed_requested_ctx_id_raises_with_reason_malformed():
    """The *requested* side is parsed too — asking with a junk id fails closed
    instead of comparing two strings that were never ctx_ids."""
    client = _client(_serving(_envelope(BODY)))
    with pytest.raises(CtxIdBindingError) as exc:
        # One of the repo's registered malformed fixtures (uppercase authority
        # — see INTENTIONALLY_MALFORMED in tests/test_identifiers.py), so the
        # repo-wide ctx_id literal sweep accounts for it.
        await client.retrieve(_MALFORMED_CTX)
    assert exc.value.reason == "malformed"


async def test_missing_ctx_id_fails_closed():
    """A body with no ``ctx_id`` cannot be bound, so it is refused.

    Unverifiable is not acceptable: the control plane makes the same call,
    answering 502 ``CONTEXT_BINDING_UNVERIFIABLE`` rather than relaying a body
    it could not bind.
    """
    headless = {k: v for k, v in BODY.items() if k != "ctx_id"}
    client = _client(_serving(_envelope(headless), bare_body=headless))
    for drive in (lambda c: c.retrieve(CTX), lambda c: c.retrieve_body(CTX)):
        with pytest.raises(CtxIdBindingError) as exc:
            await drive(client)
        assert exc.value.reason == "unverifiable"
        assert exc.value.served_ctx_id is None


async def test_non_object_body_fails_closed():
    """``body`` present but not an object is unbindable, not ignorable."""
    client = _client(_serving({"body": "nope", "registry_state": {"status": "active"}}))
    with pytest.raises(CtxIdBindingError) as exc:
        await client.retrieve(CTX)
    assert exc.value.reason == "unverifiable"


async def test_bare_body_endpoint_shape_is_handled():
    """``/contexts/{id}/body`` returns the body itself, with no envelope.

    The extraction is *told* which shape each route serves rather than
    sniffing for a ``body`` member: a sniffing reader would see no ``body`` key
    here, conclude "nothing served", and skip the very check this route needs.
    """
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        # A bare body — no envelope, no registry_state.
        return httpx.Response(200, json=SUBSTITUTED_BODY)

    with pytest.raises(CtxIdBindingError) as exc:
        await _client(handler).retrieve_body(CTX)
    assert exc.value.reason == "mismatch"
    assert seen["path"].endswith("/body")


async def test_envelope_without_body_member_is_not_treated_as_a_body():
    """A 2xx envelope that carries no ``body`` at all has nothing to bind.

    The caller's own validation is what rejects it (``FullContext`` requires
    ``body``); the binding step must not mistake the *envelope* for the body
    and report a spurious ``unverifiable``.
    """
    client = _client(_serving({"registry_state": {"status": "active"}}))
    with pytest.raises(Exception) as exc:
        await client.retrieve(CTX)
    assert not isinstance(exc.value, CtxIdBindingError)
    # retrieve_raw does no validation, so it sees the bare envelope through.
    assert await client.retrieve_raw(CTX) == {"registry_state": {"status": "active"}}


# ── the opt-out ───────────────────────────────────────────────────────────


async def test_opt_out_flag_skips_check():
    """``verify_binding=False`` is the documented escape hatch, per call…"""
    client = _client(_serving(_envelope(SUBSTITUTED_BODY)))
    raw = await client.retrieve_raw(CTX, verify_binding=False)
    assert raw["body"]["ctx_id"] == OTHER_CTX


async def test_opt_out_is_per_call_not_sticky():
    """…and it does not disarm the next call on the same client."""
    client = _client(_serving(_envelope(SUBSTITUTED_BODY)))
    await client.retrieve_raw(CTX, verify_binding=False)
    with pytest.raises(CtxIdBindingError):
        await client.retrieve_raw(CTX)


async def test_constructor_default_can_disable_enforcement():
    """The client-wide default exists for a whole-scenario opt-out."""
    client = _client(_serving(_envelope(SUBSTITUTED_BODY)), verify_binding=False)
    assert (await client.retrieve(CTX)).body.ctx_id == OTHER_CTX


async def test_constructor_default_reaches_retrieve_raw_too():
    """The client-wide opt-out must reach *every* retrieval, not just `retrieve`.

    This pins the `verify_binding=None` (inherit) default on the per-call
    parameter. A hard `True` default there would read as "enforce" and silently
    override the constructor flag on exactly this method — the one supersession
    scenarios travel through — while `test_constructor_default_can_disable_enforcement`
    stayed green, because that one goes via `retrieve`.
    """
    client = _client(_serving(_envelope(SUBSTITUTED_BODY)), verify_binding=False)
    raw = await client.retrieve_raw(CTX)
    assert raw["body"]["ctx_id"] == OTHER_CTX


async def test_enforcement_is_on_by_default():
    """The default is the security-relevant fact: a client constructed the
    ordinary way enforces."""
    assert AcdpClient(_BASE)._verify_binding is True


# ── the extraction's own regression guard ─────────────────────────────────


async def test_retrieve_raw_returns_byte_identical_json():
    """``retrieve_raw`` must still hand back the registry's exact structure.

    This is the guard on the *extraction*, not on the binding.
    ``build_supersede_request`` is given ``retrieve_raw(...)["body"]``; if the
    shared helper ever routed the response through a Pydantic model, unset
    optionals would come back as explicit ``null``s and every supersession
    scenario would break with a content-hash mismatch that no binding test
    would catch. Compared against the wire bytes, not against a model.
    """
    # A registry that sends only the members it has — the shape whose
    # re-serialization would be lossy. `Body` declares nine optional members;
    # a model round-trip would emit every one of them as an explicit null.
    lean = {k: v for k, v in BODY.items() if v is not None}
    assert "supersedes" not in lean, "the fixture no longer omits an optional member"
    wire = json.dumps(_envelope(lean), separators=(",", ":"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=wire, headers={"content-type": "application/json"})

    raw = await _client(handler).retrieve_raw(CTX)
    assert json.dumps(raw, separators=(",", ":")) == wire
    # Keys the registry did not send must not have materialised.
    assert set(raw["body"]) == set(lean)

    # And prove the guard bites: the model path really does differ, so a
    # regression here would be caught rather than being a tautology.
    from acdp_client.models import FullContext

    assert FullContext.model_validate(raw).body.model_dump()["supersedes"] is None


async def test_retrieve_raw_preserves_unknown_members():
    """Forward-compatible additions survive the chokepoint untouched."""

    def handler(request: httpx.Request) -> httpx.Response:
        payload = dict(_envelope(BODY), future_member={"nested": [1, 2, 3]})
        return httpx.Response(200, json=payload)

    raw = await _client(handler).retrieve_raw(CTX)
    assert raw["future_member"] == {"nested": [1, 2, 3]}


async def test_lifecycle_still_splices_the_signed_event_verbatim():
    """The extraction must not have cost ``_lifecycle`` its verbatim POST.

    The registry hashes the event *as received* (RFC-ACDP-0013 §5), so the
    client may never re-serialize what the producer signed.
    """
    seen: dict[str, str] = {}
    event_json = '{"event_type":"retracted","ctx_id":"' + CTX + '","z":1,"a":2}'

    def handler(request: httpx.Request) -> httpx.Response:
        seen["raw"] = request.content.decode()
        seen["method"] = request.method
        return httpx.Response(200, json=_envelope(BODY))

    await _client(handler).retract(CTX, event_json)
    assert seen["method"] == "POST"
    assert seen["raw"] == '{"event":' + event_json + "}"


# ── lineage routes ────────────────────────────────────────────────────────


async def test_lineage_routes_validate_served_id_form():
    """``/lineages/*`` is keyed by ``lineage_id``, so there is no requested
    ``ctx_id`` to compare against — but a malformed served id is still caught
    here rather than further downstream, where 0.14.1 parses ``derived_from``
    entries inside ``build_publish_request``.
    """
    broken = dict(BODY, ctx_id="ctx-42")

    def handler(request: httpx.Request) -> httpx.Response:
        payload = (
            _envelope(broken) if request.url.path.endswith("/current") else [_envelope(broken)]
        )
        return httpx.Response(200, json=payload)

    client = _client(handler)
    for drive in (lambda c: c.current(LINEAGE), lambda c: c.lineage(LINEAGE)):
        with pytest.raises(CtxIdBindingError) as exc:
            await drive(client)
        assert exc.value.reason == "malformed"
        assert exc.value.requested_ctx_id is None


async def test_lineage_routes_accept_conformant_ids():
    """Positive control: a lineage of well-formed contexts passes.

    Two *different* ctx_ids in one lineage is the normal case — the lineage
    routes must never compare them to each other. Both still carry the
    requested ``lineage_id`` — that *is* compared (see
    ``test_lineage_routes_reject_a_foreign_lineage`` below).
    """
    same_lineage_other_ctx = dict(SUBSTITUTED_BODY, lineage_id=LINEAGE)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/current"):
            return httpx.Response(200, json=_envelope(same_lineage_other_ctx))
        return httpx.Response(200, json=[_envelope(BODY), _envelope(same_lineage_other_ctx)])

    client = _client(handler)
    assert (await client.current(LINEAGE)).body.ctx_id == OTHER_CTX
    assert [c.body.ctx_id for c in await client.lineage(LINEAGE)] == [CTX, OTHER_CTX]


async def test_lineage_routes_reject_a_foreign_lineage():
    """The one thing the caller actually asked for — ``lineage_id`` — is
    checked, even though the served ``ctx_id`` need not match anything.

    A registry that answers a request for ``LINEAGE`` with a body from a
    wholly different (but internally honest — correctly signed, ctx_id-bound)
    lineage must be rejected. Without this, only the served id's *form* is
    checked on these routes, not its identity.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        payload = (
            _envelope(SUBSTITUTED_BODY)
            if request.url.path.endswith("/current")
            else [_envelope(SUBSTITUTED_BODY)]
        )
        return httpx.Response(200, json=payload)

    client = _client(handler)
    for drive in (lambda c: c.current(LINEAGE), lambda c: c.lineage(LINEAGE)):
        with pytest.raises(CtxIdBindingError) as exc:
            await drive(client)
        assert exc.value.reason == "mismatch"
        assert exc.value.requested_ctx_id == LINEAGE
        assert exc.value.served_ctx_id == SUBSTITUTED_BODY["lineage_id"]


# ── cross-registry ────────────────────────────────────────────────────────


async def test_cross_registry_retrieval_compares_requested_not_configured():
    """S5/S8 read from a *second* authority.

    The served id's authority then differs from this client's own — which is
    correct and must not trip the check. The comparison is requested-vs-served,
    never authority-vs-config.
    """
    foreign_ctx = synthetic_ctx_id("registry-b.playground.local", "ctx-binding:foreign")
    foreign_body = mock_body(
        authority="registry-b.playground.local",
        seed="ctx-binding:foreign",
        ctx_id=foreign_ctx,
    )
    client = _client(_serving(_envelope(foreign_body)))
    assert (await client.retrieve(foreign_ctx)).body.ctx_id == foreign_ctx


# ── the typed error is greppable ──────────────────────────────────────────


def test_error_is_a_runtime_error_so_sdk_guarded_scenarios_still_see_it():
    """``playground.scenarios._sdk_guard.SDK_REJECTIONS`` allow-lists
    ``RuntimeError``; the binding error must land inside it, or a scenario's
    ``expect_rejection`` would let it escape as an unhandled run error."""
    from playground.scenarios._sdk_guard import SDK_REJECTIONS

    assert issubclass(CtxIdBindingError, RuntimeError)
    assert isinstance(
        CtxIdBindingError("mismatch", requested=CTX, served=OTHER_CTX), SDK_REJECTIONS
    )
