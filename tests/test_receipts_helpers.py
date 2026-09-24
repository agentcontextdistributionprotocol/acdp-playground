"""`synthesize_retrieval_body` — the served half a minted receipt attests.

A registry receipt binds a *body*: RFC-ACDP-0010 §8 cross-checks the receipt's
``lineage_id`` / ``origin_registry`` / ``created_at`` against the body the
registry served. The scenarios that mint receipts offline have historically had
no body at all — s23 builds its receipt from literals, s27 from a bare
``content_hash`` — so there was nothing to cross-check against and no test that
the shape they *would* serve is one the SDK accepts.

These tests pin the helper that closes that: the overlay is applied to a real
``build_publish_request`` output, the producer's integrity half is never
touched, and the three authoring mistakes that would otherwise surface far from
their cause as a confusing verifier error — a duplicated registry field, a
supersede spliced into the wrong lineage, and a non-canonical ``created_at`` —
fail at the boundary instead.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from acdp import AcdpProducer, AcdpVerifier

from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id
from playground.scenarios._receipts import (
    _REGISTRY_ONLY_FIELDS,
    synthesize_retrieval_body,
)
from tests._bodies import BODY_REQUIRED_FIELDS, MOCK_CREATED_AT, PLAYGROUND_AUTHORITY, mock_producer

#: Namespaces every seed in this module so its identities never collide with
#: another fixture's.
SEED_PREFIX = "receipts-helpers"

#: Both producer identity forms the helper has to cope with. ``did:key`` is
#: self-certifying, so ``verify_body_offline`` completes; ``did:web`` needs a
#: resolver the offline verifier does not have, which is the one SDK rejection
#: the helper tolerates.
PRODUCER_KINDS = ("did:key", "did:web")

#: The fields the helper overlays unconditionally — ``Body`` minus
#: ``PublishRequest``, with ``lineage_id`` excluded because it is the one field
#: both types declare. Spelled out here rather than only imported so the test
#: asserts against the set the plan reasoned about, not against whatever the
#: helper currently happens to list.
UNCONDITIONAL_FIELDS = ("ctx_id", "origin_registry", "created_at")


def _producer(kind: str, seed: str) -> AcdpProducer:
    if kind == "did:key":
        return AcdpProducer.from_seed_did_key(
            hashlib.sha256(f"{SEED_PREFIX}:{seed}".encode()).digest()
        )
    return mock_producer(PLAYGROUND_AUTHORITY, f"{SEED_PREFIX}:{seed}")


def _publish_request(producer: AcdpProducer, **kwargs) -> str:
    """A real, signed v1 publish request — never a hand-built stand-in."""
    return producer.build_publish_request(
        title="phase-3 synthesized body",
        context_type="data_snapshot",
        visibility="public",
        **kwargs,
    )


def _identity(seed: str) -> tuple[str, str]:
    """The ``(ctx_id, lineage_id)`` pair a registry would assign for ``seed``."""
    return (
        synthetic_ctx_id(PLAYGROUND_AUTHORITY, f"{SEED_PREFIX}:{seed}"),
        synthetic_lineage_id(f"{SEED_PREFIX}:{seed}"),
    )


def _synthesize(
    request_json: str,
    seed: str,
    *,
    ctx_id: str | None = None,
    lineage_id: str | None = None,
    origin_registry: str = PLAYGROUND_AUTHORITY,
    created_at: str = MOCK_CREATED_AT,
) -> dict:
    """Call the helper with the registry assignment ``seed`` would receive.

    The overrides are spelled as real parameters rather than a ``**kwargs``
    dict so this module never contains a brace literal shaped like a body
    fixture — that shape is what
    ``test_every_inline_body_fixture_routes_through_the_factory`` sweeps for,
    and a keyword bundle tripping it would only teach the next reader to
    weaken the guard.
    """
    default_ctx_id, default_lineage_id = _identity(seed)
    return synthesize_retrieval_body(
        request_json,
        ctx_id=ctx_id or default_ctx_id,
        lineage_id=lineage_id or default_lineage_id,
        origin_registry=origin_registry,
        created_at=created_at,
    )


# ── the body the helper returns ──────────────────────────────────────────────


@pytest.mark.parametrize("kind", PRODUCER_KINDS)
def test_synthesized_body_verifies_offline(kind: str):
    """The result is a body the SDK deserializes and (for did:key) verifies.

    ``verify_body_offline`` deserializes into ``Body`` proper
    (``acdp-rs/bindings/acdp-py/src/verifier.rs:236``), so it is total over the
    required fields — unlike ``verify_content_hash``, which deserializes to a
    bare ``serde_json::Value`` and would pass a body missing half its schema.
    For ``did:web`` the same call can only reach key resolution, which is the
    documented offline limitation and not a defect in the body.
    """
    producer = _producer(kind, "verifies-offline")
    body = _synthesize(_publish_request(producer), "verifies-offline")

    missing = [field for field in BODY_REQUIRED_FIELDS if field not in body]
    assert not missing, f"synthesized body omits SDK-required Body fields {missing}"

    if kind == "did:key":
        assert AcdpVerifier.verify_body_offline(json.dumps(body)) is True
    else:
        with pytest.raises(RuntimeError, match="did:key producers only"):
            AcdpVerifier.verify_body_offline(json.dumps(body))


def test_content_hash_is_preserved():
    """The overlay leaves the producer's integrity half byte-identical.

    The registry-assigned fields sit outside the ``content_hash`` preimage
    (RFC-ACDP-0001 §5.7), so a body that re-hashed differently from the request
    it was built from would mean the helper had touched producer content.
    """
    producer = _producer("did:key", "hash-preserved")
    request_json = _publish_request(producer)
    request = json.loads(request_json)

    body = _synthesize(request_json, "hash-preserved")

    assert body["content_hash"] == request["content_hash"]
    assert body["signature"] == request["signature"]
    assert AcdpVerifier.verify_content_hash(json.dumps(body), body["content_hash"]) is True


# ── the overlay rules ────────────────────────────────────────────────────────


@pytest.mark.parametrize("field", UNCONDITIONAL_FIELDS)
def test_duplicate_registry_field_rejected(field: str):
    """A request already carrying a registry-assigned field means the schema moved.

    ``PublishRequest`` declares none of these three
    (``acdp-rs/crates/acdp-types/src/publish.rs:26-64``), so silently
    overwriting one would hide a real change behind a passing run. The
    equality assertion pins the set itself: ``Body`` \\ ``PublishRequest`` is
    three fields plus the ``lineage_id`` carve-out below, and a fourth joining
    it must show up here rather than slipping past uncovered.
    """
    assert _REGISTRY_ONLY_FIELDS == UNCONDITIONAL_FIELDS
    producer = _producer("did:key", f"duplicate-{field}")
    request = json.loads(_publish_request(producer))
    request[field] = "already here"

    with pytest.raises(ValueError, match=field):
        _synthesize(json.dumps(request), f"duplicate-{field}")


def test_v1_request_gets_lineage_id_set():
    """v1 publications MUST NOT carry `lineage_id`, so the helper assigns it."""
    producer = _producer("did:key", "v1-lineage")
    request_json = _publish_request(producer)
    assert "lineage_id" not in json.loads(request_json)

    body = _synthesize(request_json, "v1-lineage")

    _, expected = _identity("v1-lineage")
    assert body["lineage_id"] == expected
    assert body["version"] == 1


def test_v2_request_with_matching_lineage_id_is_accepted():
    """A supersede request *does* carry `lineage_id`, and that is legitimate.

    ``new_version_from`` pre-fills the self-verification value from the
    previous body (``acdp-rs/crates/acdp-producer/src/builder.rs:136``), so a
    blanket "raise if already present" rule would reject every v2+ body the
    catalog builds — s7, s15, s17 and s28 among them.
    """
    producer = _producer("did:key", "v2-matching")
    v1 = _synthesize(_publish_request(producer), "v2-matching")
    _, lineage_id = _identity("v2-matching")

    v2_request = json.loads(producer.build_supersede_request(json.dumps(v1), title="version two"))
    assert v2_request["lineage_id"] == lineage_id

    v2 = _synthesize(
        json.dumps(v2_request),
        "v2-matching",
        ctx_id=synthetic_ctx_id(PLAYGROUND_AUTHORITY, f"{SEED_PREFIX}:v2-matching:2"),
    )

    assert v2["lineage_id"] == lineage_id
    assert v2["version"] == 2
    assert v2["supersedes"] == v1["ctx_id"]
    assert AcdpVerifier.verify_body_offline(json.dumps(v2)) is True


def test_v2_request_with_conflicting_lineage_id_raises():
    """Superseding into the wrong lineage is an authoring bug, not a merge."""
    producer = _producer("did:key", "v2-conflicting")
    v1 = _synthesize(_publish_request(producer), "v2-conflicting")
    v2_request = producer.build_supersede_request(json.dumps(v1), title="version two")

    with pytest.raises(ValueError, match="lineage_id"):
        _synthesize(
            v2_request,
            "v2-conflicting",
            lineage_id=synthetic_lineage_id(f"{SEED_PREFIX}:some-other-lineage"),
        )


@pytest.mark.parametrize(
    ("created_at", "why"),
    [
        ("2026-06-01T00:00:00.000+00:00", "numeric offset instead of 'Z'"),
        ("2026-06-01T00:00:00.123456Z", "microsecond precision"),
        ("2026-06-01T00:00:00.000", "no timezone designator at all"),
        ("2026-06-01T00:00:00Z", "second precision, no fractional digits"),
    ],
)
def test_noncanonical_created_at_rejected(created_at: str, why: str):
    """Only `…SS.mmmZ` is accepted — `Body` is permissive, receipts are not.

    ``RegistryReceipt::created_at`` serializes through ``ms_rfc3339``
    (``acdp-rs/crates/acdp-types/src/receipt.rs:177``); a body carrying any
    other byte form deserializes fine but fails RFC-ACDP-0010 §8 step 6 once a
    receipt is minted against it, far from the line that authored it.
    """
    producer = _producer("did:key", "created-at")

    with pytest.raises(ValueError, match="millisecond-precision") as caught:
        _synthesize(_publish_request(producer), "created-at", created_at=created_at)

    assert "YYYY-MM-DDTHH:MM:SS.mmmZ" in str(caught.value), why


# ── the round-trip guard ─────────────────────────────────────────────────────


@pytest.mark.parametrize("kind", PRODUCER_KINDS)
def test_body_round_trips_through_verify_content_hash(kind: str):
    """The helper cannot hand back a body whose hash does not recompute.

    This is the invariant that matters for ``did:web`` producers, where
    ``verify_body_offline`` stops at key resolution: ``verify_content_hash``
    re-canonicalizes the producer content and is then the only thing between a
    mangled request and a returned body. It is not a tautology — hash coverage
    excludes all four overlaid fields, so it is genuinely re-checking the input.
    """
    producer = _producer(kind, f"round-trip-{kind}")
    request = json.loads(_publish_request(producer))

    body = _synthesize(json.dumps(request), f"round-trip-{kind}")
    assert AcdpVerifier.verify_content_hash(json.dumps(body), body["content_hash"]) is True

    tampered = json.dumps({**request, "title": "edited after signing"})
    with pytest.raises(RuntimeError):
        _synthesize(tampered, f"round-trip-{kind}")


@pytest.mark.parametrize("kind", PRODUCER_KINDS)
def test_schema_violation_in_an_overlaid_field_raises(kind: str):
    """The internal ``verify_body_offline`` call is load-bearing, not decorative.

    A malformed ``origin_registry`` is invisible to ``verify_content_hash`` —
    the four overlaid fields sit outside the hash preimage — so this is the one
    class only the ``Body`` deserialization plus ``validate_body`` can catch.
    It runs before the ``did:key`` short-circuit, so it bites for both producer
    kinds. Without it the helper would hand back a body the SDK rejects, and
    the caller would find out much later, inside a receipt cross-check.
    """
    producer = _producer(kind, f"schema-violation-{kind}")

    with pytest.raises(RuntimeError, match="schema violation"):
        _synthesize(
            _publish_request(producer),
            f"schema-violation-{kind}",
            origin_registry="REGISTRY-A.Playground.Local:8443",
        )
