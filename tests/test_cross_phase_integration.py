"""The seam between phases 2–5 of the 0.14 catch-up, driven as one flow.

Every phase of that plan landed with its own unit tests, and each of those
tests exercises its phase in isolation: :mod:`tests.test_identifiers` mints ids
and never serves them, :mod:`tests.test_receipts_helpers` synthesizes a body
and never retrieves it, :mod:`tests.test_client_ctx_binding` retrieves bodies
built by :func:`tests._bodies.mock_body` and never mints a receipt against one.
Nothing asserted that the four *compose* — that a body carrying Phase 2's
conformant identifiers, built by Phase 3's synthesizer out of a real signed
publish request, actually reaches Phase 5's transport chokepoint and is then
cross-checked by the Phase 4 receipt call on those same served bytes.

So this module runs the whole chain end to end against an
:class:`httpx.MockTransport` registry:

    Phase 2  synthetic_ctx_id / synthetic_lineage_id
      → real AcdpProducer.build_publish_request (signed, hashed)
      → Phase 3  synthesize_retrieval_body (the served body)
      → a registry that serves it
      → Phase 5  AcdpClient._get_full_context → verify_ctx_id_binding
      → Phase 4  AcdpVerifier.verify_receipt(receipt, BODY, …) — six arguments

and then pins the three ways that chain can rot: a Phase-2 regression caught
downstream by Phase 5, a Phase-3 regression caught downstream by Phase 4, and
the independence of those two checks — neither may mask the other.

**Every assertion here names a type and a wording.** ``CtxIdBindingError``
subclasses ``RuntimeError`` and therefore sits *inside*
``playground.scenarios._sdk_guard.SDK_REJECTIONS`` right next to ``ValueError``,
so "it raised" is not evidence that the control under test is the one that
fired: a malformed identifier, a working security check and a broken call
signature are indistinguishable from a bare raise.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, NamedTuple

import httpx
import pytest
from acdp import AcdpProducer, AcdpVerifier

from acdp_client import AcdpClient, CtxIdBindingError
from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id
from playground.scenarios._receipts import mint_receipt, synthesize_retrieval_body

#: Namespaces every seed in this module so its identities never collide with
#: another fixture's — the same discipline ``tests/test_receipts_helpers.py``
#: uses.
SEED_PREFIX = "cross-phase"

AUTHORITY = "registry-a.playground.local"
#: A second authority, for the one case that needs a body attributed elsewhere.
OTHER_AUTHORITY = "registry-b.playground.local"
BASE_URL = f"http://{AUTHORITY}"

#: Canonical millisecond RFC 3339 — the only byte form Phase 3 accepts, and the
#: one RFC-ACDP-0010 §8 step 6 requires of a receipt.
CREATED_AT = "2026-06-01T00:00:00.000Z"

REGISTRY_DID = f"did:web:{AUTHORITY}"
RECEIPT_KEY_ID = f"{REGISTRY_DID}#receipt-key-1"

#: The pre-Phase-2 identifier shape this repo used to ship: a scheme, a
#: one-label authority, and ``1`` where a v4 UUID belongs. Taken from
#: ``INTENTIONALLY_MALFORMED`` in ``tests/test_identifiers.py`` rather than
#: minted here, so the repo-wide literal sweep already accounts for it and the
#: string under test is the exact one the fixtures carried.
NONCONFORMANT_CTX_ID = "acdp://r/1"


class Published(NamedTuple):
    """One context as it exists on both sides of a publish.

    ``request`` is the producer's signed wire JSON; ``body`` is what a registry
    serves for it. Keeping both lets a test assert that Phase 3 only ever
    *overlays* — it never re-signs or re-hashes.
    """

    producer: AcdpProducer
    ctx_id: str
    lineage_id: str
    request: str
    body: dict[str, Any]

    @property
    def fingerprint(self) -> str:
        """The producer key fingerprint a registry records at publish time."""
        return AcdpVerifier.fingerprint_ed25519_b64(self.producer.public_key_b64)


def _producer(name: str) -> AcdpProducer:
    """A deterministic ``did:key`` producer.

    ``did:key`` is self-certifying, so a synthesized body verifies *fully*
    offline — ``verify_body_offline`` reaches the signature instead of stopping
    at key resolution the way it must for ``did:web``. That matters here: this
    module's claim is that the composed chain is sound end to end, and a
    producer whose signature cannot be checked offline would leave a hole in
    the middle of it.
    """
    return AcdpProducer.from_seed_did_key(hashlib.sha256(f"{SEED_PREFIX}:{name}".encode()).digest())


def _registry_signer() -> AcdpProducer:
    """The registry's Ed25519 receipt-signing key, deterministic per module."""
    return AcdpProducer.from_seed(
        hashlib.sha256(f"{SEED_PREFIX}:registry-receipt-key".encode()).digest(),
        REGISTRY_DID,
        RECEIPT_KEY_ID,
    )


def _publish(name: str, *, producer: AcdpProducer | None = None, lineage: str | None = None):
    """Phases 2 and 3, composed: mint the ids, sign for real, overlay the body.

    The identifiers come from the Phase 2 minter (never a literal), the signed
    half comes from the SDK (never a hand-built dict), and the registry-assigned
    half is overlaid by the Phase 3 helper — which re-verifies the result
    through ``verify_body_offline`` + ``verify_content_hash`` before returning
    it. A body that reaches a test from here is one the SDK accepts.
    """
    producer = producer or _producer(name)
    ctx_id = synthetic_ctx_id(AUTHORITY, f"{SEED_PREFIX}:{name}")
    lineage_id = lineage or synthetic_lineage_id(f"{SEED_PREFIX}:{name}")
    request = producer.build_publish_request(
        title=f"cross-phase {name}",
        context_type="analysis",
        visibility="public",
        summary="the body a registry serves across the phase seam",
        domain="provenance",
        tags=["cross-phase"],
    )
    body = synthesize_retrieval_body(
        request,
        ctx_id=ctx_id,
        lineage_id=lineage_id,
        origin_registry=AUTHORITY,
        created_at=CREATED_AT,
    )
    return Published(producer, ctx_id, lineage_id, request, body)


def _receipt(published: Published, body: dict[str, Any] | None = None) -> dict:
    """The receipt a receipts-profile registry would attach to ``body``.

    Defaults to attesting ``published.body``; pass ``body`` explicitly to mint
    a receipt that is *honest about a different body*, which is how the §8
    step 3 cases below stay internally consistent right up to the body binding.
    """
    attested = published.body if body is None else body
    return mint_receipt(
        _registry_signer(),
        RECEIPT_KEY_ID,
        registry_did=REGISTRY_DID,
        ctx_id=attested["ctx_id"],
        lineage_id=attested["lineage_id"],
        origin_registry=attested["origin_registry"],
        created_at=attested["created_at"],
        content_hash=attested["content_hash"],
        key_fingerprint=published.fingerprint,
    )


def _verify_receipt(receipt: dict, body: dict[str, Any], *, expected_ctx_id: str, fingerprint: str):
    """Phase 4's call, with all six 0.14.1 arguments.

    ``recomputed_body_hash`` is the body's own ``content_hash`` only *after*
    ``verify_content_hash`` has re-derived it from the served bytes — the SDK
    docstring is explicit that the echoed field must never be passed on faith.
    """
    body_json = json.dumps(body)
    AcdpVerifier.verify_content_hash(body_json, body["content_hash"])
    return AcdpVerifier.verify_receipt(
        json.dumps(receipt),
        body_json,
        _registry_signer().public_key_b64,
        expected_ctx_id,
        body["content_hash"],
        fingerprint,
    )


def _registry(body: dict[str, Any], receipt: dict | None = None):
    """A registry that answers every context read with ``body``.

    Receipt-*less* by default, which is the common case the RFC-ACDP-0006 §4.1
    step 7 binding exists for: with no receipt served, none of the §8 gates
    apply and the requested-vs-served ``ctx_id`` comparison is the only thing
    between the caller and a substituted context.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        envelope: dict[str, Any] = {"body": body, "registry_state": {"status": "active"}}
        if receipt is not None:
            envelope["registry_receipt"] = receipt
        return httpx.Response(200, json=envelope, request=request)

    return handler


def _client(handler) -> AcdpClient:
    """The **real** client, so the Phase 5 chokepoint is genuinely in the path.

    Only the transport is a stand-in. Nothing here reimplements retrieval, which
    is the whole point: a test that called ``verify_ctx_id_binding`` directly
    would prove the SDK works and say nothing about whether the playground's
    retrieval path reaches it.
    """
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=BASE_URL)
    return AcdpClient(BASE_URL, http=http)


# ── 1. the happy path composes ───────────────────────────────────────────────


async def test_the_whole_chain_composes_on_the_happy_path():
    """Phases 2 → 3 → 5 → 4, one flow, each stage asserted.

    The closing half is the positive control, and it is not optional: every
    assertion above would still pass with the §4.1 step 7 binding deleted
    outright, because an honest registry never trips it. So the same client,
    against the same flow, is shown refusing a *substituted* body — proving the
    check was armed while the happy path ran through it, rather than absent.
    """
    published = _publish("happy")
    receipt = _receipt(published)

    # Phase 2 produced ids the SDK's own parser accepts — which is what lets
    # this body exist at all (Phase 3 re-verifies before returning it).
    assert published.body["ctx_id"] == published.ctx_id
    assert published.body["lineage_id"] == published.lineage_id

    # Phase 3 overlaid identity without touching the signed half.
    signed = json.loads(published.request)
    assert published.body["content_hash"] == signed["content_hash"]
    assert published.body["signature"] == signed["signature"]

    client = _client(_registry(published.body, receipt))

    # Phase 5: the transport chokepoint, on the validated and the raw route.
    full = await client.retrieve(published.ctx_id)
    assert full.body.ctx_id == published.ctx_id
    raw = await client.retrieve_raw(published.ctx_id)
    served = raw["body"]
    assert served == published.body, "the chokepoint must return the registry's JSON verbatim"

    # The served bytes verify on their own terms before any receipt is trusted.
    assert AcdpVerifier.verify_body_offline(json.dumps(served)) is True

    # Phase 4: §8, including step 3's cross-check against *that* served body.
    assert (
        _verify_receipt(
            raw["registry_receipt"],
            served,
            expected_ctx_id=published.ctx_id,
            fingerprint=published.fingerprint,
        )
        is True
    )

    # The positive control. A second context by the same producer, just as
    # valid and just as well attested — served under the first one's id.
    substitute = _publish("happy-substitute", producer=published.producer)
    substituting = _client(_registry(substitute.body, _receipt(substitute)))
    with pytest.raises(CtxIdBindingError) as exc:
        await substituting.retrieve(published.ctx_id)
    assert exc.value.reason == "mismatch"
    assert exc.value.requested_ctx_id == published.ctx_id
    assert exc.value.served_ctx_id == substitute.ctx_id


# ── 2. a Phase-2 regression is caught by Phase 5 ─────────────────────────────


async def test_a_nonconformant_identifier_cannot_survive_the_chain():
    """The fixtures could not silently regress to the pre-0.14 id shape.

    Phase 2 swept ids like ``acdp://r/1`` out of the repo because 0.14.x parses
    ``ctx_id`` strictly and they had sat green for releases. Two independent
    layers now stand between such an id and a passing run, and both are pinned
    here: Phase 3 refuses to *build* a body around one, and — for the shapes
    that never go through the synthesizer at all, which is exactly how the old
    literals entered — Phase 5 refuses to accept one off the wire.

    ``reason == "malformed"`` is the load-bearing half. ``CtxIdBindingError``
    is a ``RuntimeError``, so a bare raise here would be equally satisfied by
    the substitution check working correctly; only the reason separates "the
    registry lied" from "this identifier was never well-formed".
    """
    published = _publish("phase2-regression")

    # Layer one: the synthesizer will not mint it. The SDK deserializes the
    # overlaid body into `Body`, which CtxId::parses the field.
    with pytest.raises(RuntimeError, match="ctx_id") as built:
        synthesize_retrieval_body(
            published.request,
            ctx_id=NONCONFORMANT_CTX_ID,
            lineage_id=published.lineage_id,
            origin_registry=AUTHORITY,
            created_at=CREATED_AT,
        )
    assert "schema violation" in str(built.value)

    # Layer two: one that reached the wire regardless is refused on retrieval.
    regressed = dict(published.body, ctx_id=NONCONFORMANT_CTX_ID)
    with pytest.raises(CtxIdBindingError) as exc:
        await _client(_registry(regressed)).retrieve(NONCONFORMANT_CTX_ID)
    assert exc.value.reason == "malformed"
    assert exc.value.served_ctx_id == NONCONFORMANT_CTX_ID

    # And a conformant request against that same regressed body is *also*
    # malformed, not a mismatch: the served id never parsed, so there was
    # nothing to compare.
    with pytest.raises(CtxIdBindingError) as asked_properly:
        await _client(_registry(regressed)).retrieve(published.ctx_id)
    assert asked_properly.value.reason == "malformed"


# ── 3. a Phase-3 regression is caught by Phase 4 ─────────────────────────────

#: The three fields Phase 3 overlays that RFC-ACDP-0010 §8 step 3 binds a
#: receipt to. ``ctx_id`` is the fourth overlaid field and is deliberately
#: absent: it is bound by §8 step 2 *and* by Phase 5, so it could not show
#: which of the two fired. Each replacement value is itself well-formed, so the
#: body still deserializes and still hashes true — the drift is visible to
#: nothing but the body cross-check.
DRIFTED_OVERLAY_FIELDS = (
    ("lineage_id", synthetic_lineage_id(f"{SEED_PREFIX}:a-lineage-this-body-is-not-in")),
    ("origin_registry", OTHER_AUTHORITY),
    ("created_at", "2026-06-02T00:00:00.000Z"),
)


@pytest.mark.parametrize(("field", "drifted_value"), DRIFTED_OVERLAY_FIELDS)
async def test_a_drifted_overlay_field_is_caught_by_the_receipt_cross_check(
    field: str, drifted_value: str
):
    """If Phase 3's overlay drifted, Phase 4 is what notices.

    These three fields sit outside the ``content_hash`` preimage
    (RFC-ACDP-0001 §5.7), so the producer's integrity half says nothing about
    them; ``verify_body_offline`` accepts every value used here; and the served
    ``ctx_id`` is untouched, so Phase 5 waves the body through. The receipt's
    body binding — which only exists because 0.14.1 made ``verify_receipt``
    take the served body — is the sole remaining check, and the assertion
    matches ``cross_check_body``'s own "≠ **body** <field>" wording, which no
    other §8 gate emits.
    """
    published = _publish("phase3-regression")
    receipt = _receipt(published)  # honest: minted against the undrifted body
    drifted = dict(published.body, **{field: drifted_value})

    # Phase 5 is live on this call and has no objection — the id still binds.
    served = (await _client(_registry(drifted, receipt)).retrieve_raw(published.ctx_id))["body"]
    assert served[field] == drifted_value

    with pytest.raises(RuntimeError) as exc:
        _verify_receipt(
            receipt,
            served,
            expected_ctx_id=published.ctx_id,
            fingerprint=published.fingerprint,
        )
    assert f"body {field}" in str(exc.value)
    assert not isinstance(exc.value, CtxIdBindingError)


# ── 4. the two checks are independent ────────────────────────────────────────


async def test_the_binding_and_the_receipt_cross_check_do_not_mask_each_other():
    """Two failures, two different origins, correctly attributed.

    The risk when two checks run over the same bytes is that one is doing the
    other's work — that the suite would stay green with either deleted. So:

    * **(a)** a body whose ``ctx_id`` binds honestly but whose ``lineage_id``
      the receipt disowns. Phase 5 passes it; only §8 step 3 rejects it.
    * **(b)** a body served *with no receipt at all* — the receipt-less path,
      which is most of the world — that is genuinely, verifiably attested on
      its own terms, and is simply not the context that was requested. Phase 4
      has nothing to run; only Phase 5 rejects it.

    Case (b) asserts the counterfactual directly: the substituted body's own
    receipt is checked and *passes* against its own id, so nothing about that
    body is wrong. Delete the binding and the retrieval succeeds silently.
    """
    honest = _publish("independence-honest")

    # (a) binding passes, receipt cross-check fails.
    receipt = _receipt(honest)
    disowned = dict(honest.body, lineage_id=synthetic_lineage_id(f"{SEED_PREFIX}:foreign-lineage"))
    served = (await _client(_registry(disowned, receipt)).retrieve_raw(honest.ctx_id))["body"]
    with pytest.raises(RuntimeError) as receipt_failure:
        _verify_receipt(
            receipt, served, expected_ctx_id=honest.ctx_id, fingerprint=honest.fingerprint
        )

    # (b) binding fails on a body whose receipt would have verified.
    substitute = _publish("independence-substitute", producer=honest.producer)
    substitute_receipt = _receipt(substitute)
    assert (
        _verify_receipt(
            substitute_receipt,
            substitute.body,
            expected_ctx_id=substitute.ctx_id,
            fingerprint=substitute.fingerprint,
        )
        is True
    ), "the substituted body must be beyond reproach on its own terms"

    with pytest.raises(CtxIdBindingError) as binding_failure:
        await _client(_registry(substitute.body)).retrieve(honest.ctx_id)

    # Neither verdict is the other's.
    assert not isinstance(receipt_failure.value, CtxIdBindingError)
    assert "body lineage_id" in str(receipt_failure.value)
    assert "ctx_id binding" not in str(receipt_failure.value)

    assert binding_failure.value.reason == "mismatch"
    assert binding_failure.value.requested_ctx_id == honest.ctx_id
    assert binding_failure.value.served_ctx_id == substitute.ctx_id
    assert "lineage_id" not in str(binding_failure.value)


# ── 5. supersession survives the chokepoint ──────────────────────────────────


async def test_supersession_round_trips_through_the_binding_chokepoint():
    """``retrieve_raw`` stayed byte-exact when Phase 5 collapsed four bodies
    into one, and a v2 built from those bytes still verifies.

    ``build_supersede_request`` consumes the previous body's *exact* registry
    bytes. Routing the shared chokepoint through a Pydantic model would emit
    every unset optional as an explicit ``null``, and the SDK then refuses the
    body outright (``invalid type: null, expected a string``) — a break no
    binding assertion would catch, because the binding would still pass. The
    equality against a supersede built from the un-retrieved body is the pin:
    it fails on any re-serialization, lossy or not.

    The chain is then closed rather than left at the request: the v2 request is
    overlaid by Phase 3 into the body a registry would serve, retrieved through
    the same chokepoint under its own Phase-2 id, and attested by a receipt
    that Phase 4 verifies against those served bytes.
    """
    v1 = _publish("supersede-v1")
    client = _client(_registry(v1.body))
    assert client._verify_binding is True, "the chokepoint must be armed for this to mean anything"

    raw = await client.retrieve_raw(v1.ctx_id)
    assert set(raw["body"]) == set(v1.body), "keys the registry never sent must not materialise"

    v2_request = v1.producer.build_supersede_request(json.dumps(raw["body"]), title="version two")
    assert v2_request == v1.producer.build_supersede_request(
        json.dumps(v1.body), title="version two"
    ), "retrieval through the chokepoint changed the bytes build_supersede_request sees"

    assert AcdpVerifier.verify_publish_request_offline(v2_request) is True
    parsed = json.loads(v2_request)
    assert parsed["version"] == 2
    assert parsed["supersedes"] == v1.ctx_id
    assert parsed["lineage_id"] == v1.lineage_id

    # The registry accepts v2 and serves it — through the same chokepoint.
    v2_ctx_id = synthetic_ctx_id(AUTHORITY, f"{SEED_PREFIX}:supersede-v2")
    v2_body = synthesize_retrieval_body(
        v2_request,
        ctx_id=v2_ctx_id,
        lineage_id=v1.lineage_id,
        origin_registry=AUTHORITY,
        created_at=CREATED_AT,
    )
    v2 = Published(v1.producer, v2_ctx_id, v1.lineage_id, v2_request, v2_body)
    v2_receipt = _receipt(v2)

    served = (await _client(_registry(v2_body, v2_receipt)).retrieve_raw(v2_ctx_id))["body"]
    assert served["supersedes"] == v1.ctx_id
    assert served["lineage_id"] == v1.lineage_id
    assert AcdpVerifier.verify_body_offline(json.dumps(served)) is True
    assert (
        _verify_receipt(v2_receipt, served, expected_ctx_id=v2_ctx_id, fingerprint=v2.fingerprint)
        is True
    )
