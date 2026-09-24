"""Every mock ``body`` fixture must be a body the SDK actually accepts.

Conformant ``ctx_id``\\ s are necessary but not sufficient. A served body is
deserialized into the SDK's ``Body`` struct
(``acdp-rs/crates/acdp-types/src/body.rs:22-41``), which is total over
fourteen fields — and the hand-written stub this suite shipped omitted three
of them (``contributors``, ``data_refs``, ``derived_from``) while carrying a
``"sha256:abc"`` placeholder digest. Nothing checked it, because nothing
parsed it: the offline suite only ever fed those bodies to Pydantic.

That is a fixture nobody had checked sitting directly on the retrieval path,
which is exactly what CLAUDE.md calls mock drift. These tests close it by
running each fixture through the SDK the way a consumer would.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from acdp import AcdpVerifier

from acdp_client.identifiers import is_conformant_ctx_id
from tests._bodies import (
    BODY_REQUIRED_FIELDS,
    MOCK_BODIES,
    PLAYGROUND_AUTHORITY,
    mock_body,
    mock_producer,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Files allowed to build a registry-shaped body without going through
#: :func:`tests._bodies.mock_body`, with the reason each is exempt.
_INLINE_BODY_EXEMPT: dict[str, str] = {
    "tests/_bodies.py": "the factory itself",
    "tests/test_fixtures_are_valid_bodies.py": "this guard",
    "tests/test_scenarios_mocked_registry.py": (
        "its FakeRegistry splices the registry fields onto the *real* publish "
        "request it was posted, so the body is genuine by construction"
    ),
    "tests/test_scenarios_v2.py": (
        "builds `previous_body` from a real build_publish_request output for "
        "the supersede path, same reason"
    ),
}

_INLINE_BODY_RE = re.compile(r"[\"']origin_registry[\"']\s*:")


def test_mock_bodies_catalog_is_populated():
    assert MOCK_BODIES, "the catalog is empty — this guard would pass vacuously"


@pytest.mark.parametrize("name", sorted(MOCK_BODIES))
def test_every_mock_body_deserializes(name: str):
    """Each fixture is total over ``Body``'s required fields and hashes true.

    ``AcdpVerifier.verify_content_hash`` re-canonicalizes the producer content
    and recomputes the SHA-256, so it fails on a placeholder digest, on a
    mangled producer field, and on a malformed ``content_hash`` envelope. The
    required-field assertion covers the one class it does *not* see — a field
    absent from both the body and its hash preimage — which is precisely the
    class the old stub was in.
    """
    body = MOCK_BODIES[name]

    missing = [field for field in BODY_REQUIRED_FIELDS if field not in body]
    assert not missing, (
        f"{name} omits SDK-required Body fields {missing}; a consumer "
        f"deserializing it raises ValueError before any check runs"
    )

    # Delegate the same totality question to the SDK, so the hand-written
    # tuple above cannot silently go stale against `Body`. `verify_body_offline`
    # is the 0.8.3 entry point that deserializes into `Body` proper — the same
    # thing Phase 5's `verify_ctx_id_binding` does — so a missing required field
    # surfaces here as `ValueError: missing field '…'`. A `RuntimeError` is the
    # expected, unrelated outcome for a `did:web` producer whose key cannot be
    # resolved offline, and is not a fixture defect.
    try:
        AcdpVerifier.verify_body_offline(json.dumps(body))
    except ValueError as exc:  # pragma: no cover - only on a bad fixture
        pytest.fail(f"{name} does not deserialize as an SDK Body: {exc}")
    except RuntimeError:
        pass

    assert is_conformant_ctx_id(body["ctx_id"]), f"{name}: {body['ctx_id']}"
    assert re.fullmatch(r"lin:sha256:[0-9a-f]{64}", body["lineage_id"]), name

    assert AcdpVerifier.verify_content_hash(json.dumps(body), body["content_hash"]) is True


@pytest.mark.parametrize("field", BODY_REQUIRED_FIELDS)
def test_sdk_totality_check_actually_bites(field: str):
    """Dropping any required field must make the SDK refuse to deserialize.

    This is what keeps `BODY_REQUIRED_FIELDS` honest: if the tuple ever drifts
    from `Body`, the delegated check above still fails on the real schema.
    """
    body = dict(mock_body(authority="reg.test", seed="totality"))
    body.pop(field)
    with pytest.raises(ValueError):
        AcdpVerifier.verify_body_offline(json.dumps(body))


def test_mock_body_hash_check_actually_bites():
    """The guard above is load-bearing, not decorative.

    Mutating a producer-controlled field must break the recomputation — if it
    did not, `verify_content_hash` would be passing every fixture for free.
    """
    tampered = dict(mock_body(authority="reg.test", seed="tamper"), title="edited")
    with pytest.raises(RuntimeError):
        AcdpVerifier.verify_content_hash(json.dumps(tampered), tampered["content_hash"])


def test_derived_from_accepts_mock_minted_ctx_ids():
    """A mock-minted ctx_id survives ``build_publish_request(derived_from=…)``.

    ``derived_from`` entries go through ``CtxId::parse`` from 0.14.1 on
    (``acdp-rs/bindings/acdp-py/src/producer.rs:100-102``), so a registry mock
    that mints ids the parser rejects breaks every derivative publish in the
    suite. The mocked registry's old ``ctx-<version>`` minter was exactly
    that — see the allowlist note in ``tests/test_identifiers.py``.
    """
    parents = [body["ctx_id"] for body in MOCK_BODIES.values()]
    assert parents

    producer = mock_producer(PLAYGROUND_AUTHORITY, "derived-from-consumer")
    request = json.loads(
        producer.build_publish_request(
            title="derivative",
            context_type="analysis",
            visibility="public",
            derived_from=parents,
        )
    )

    assert request["derived_from"] == parents
    for parent in request["derived_from"]:
        assert is_conformant_ctx_id(parent), parent
    assert AcdpVerifier.verify_content_hash(json.dumps(request), request["content_hash"]) is True


def test_every_inline_body_fixture_routes_through_the_factory():
    """No new hand-written body fixture can appear outside the catalog.

    Without this the catalog is trusted rather than enforced, and the next
    inline stub would sit outside every check above — which is how the current
    one survived.
    """
    # Only the fixture trees. `playground/` legitimately names
    # `origin_registry` on *receipts* (scenarios/_receipts.py), which the SDK
    # mints and the scenarios verify — those are not mock bodies.
    offenders: list[str] = []
    swept = 0
    for root in ("tests", "scripts"):
        for path in sorted((REPO_ROOT / root).rglob("*.py")):
            rel = str(path.relative_to(REPO_ROOT))
            if rel in _INLINE_BODY_EXEMPT:
                continue
            swept += 1
            if _INLINE_BODY_RE.search(path.read_text(encoding="utf-8")):
                offenders.append(rel)

    assert swept > 20, f"the sweep only read {swept} files — it is not covering the fixtures"
    assert not offenders, (
        "inline registry-body fixtures outside tests/_bodies.py: "
        + ", ".join(offenders)
        + ". Build them with mock_body() and register them in MOCK_BODIES so "
        "they are covered by test_every_mock_body_deserializes."
    )
