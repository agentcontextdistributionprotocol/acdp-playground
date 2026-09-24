"""Deterministic, SDK-valid mock context bodies for the offline suite.

Every mocked registry in this suite has to serve a ``body`` object. Written by
hand, those bodies drifted into shapes no registry could ever emit — missing
required fields, placeholder digests like ``"sha256:abc"``, ``ctx_id``\\ s that
fail the RFC grammar. That is precisely the mock drift CLAUDE.md names as the
harness's standing risk, and it is load-bearing: the SDK deserializes a served
body into its ``Body`` struct
(``acdp-rs/crates/acdp-types/src/body.rs:20-41``), which is total over
fourteen required fields, and recomputes ``content_hash`` over the
JCS-canonicalized producer content.

So bodies are *built*, not written: :func:`mock_body` signs a real
``build_publish_request`` with a deterministic seed and splices on the four
registry-assigned fields, minting the identity pair through
``acdp_client.identifiers``. The result verifies for real.

:data:`MOCK_BODIES` is the catalog of every such fixture the suite serves;
``tests/test_fixtures_are_valid_bodies.py`` asserts each one round-trips
through the SDK, so no fixture reaches a phase that parses it unchecked.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from acdp import AcdpProducer

from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id

#: The fourteen fields `acdp`'s ``Body`` struct declares non-optional
#: (``acdp-rs/crates/acdp-types/src/body.rs:22-41``). ``supersedes`` and every
#: field below it are ``Option``, so their absence deserializes to ``None``.
BODY_REQUIRED_FIELDS: tuple[str, ...] = (
    # Registry-assigned identity (not covered by content_hash/signature).
    "ctx_id",
    "lineage_id",
    "origin_registry",
    "created_at",
    # Integrity.
    "content_hash",
    "signature",
    # Producer-controlled, required.
    "version",
    "agent_id",
    "contributors",
    "title",
    "type",
    "data_refs",
    "derived_from",
    "visibility",
)

#: A stable ``created_at`` — fixtures must not depend on wall-clock time.
MOCK_CREATED_AT = "2026-06-01T00:00:00.000Z"


def mock_producer(authority: str, seed: str, slug: str = "mock-producer") -> AcdpProducer:
    """A deterministic ``did:web`` producer for ``authority``/``seed``."""
    agent_did = f"did:web:{authority}:agents:{slug}"
    return AcdpProducer.from_seed(
        hashlib.sha256(f"mock-body:{authority}:{seed}".encode()).digest(),
        agent_did,
        f"{agent_did}#key-1",
    )


def mock_body(
    *,
    authority: str,
    seed: str,
    title: str = "mock context",
    context_type: str = "data_snapshot",
    visibility: str = "public",
    slug: str = "mock-producer",
    ctx_id: str | None = None,
    created_at: str = MOCK_CREATED_AT,
    **publish_kwargs: Any,
) -> dict[str, Any]:
    """Build a registry-shaped ``body`` that the SDK actually accepts.

    ``ctx_id`` defaults to ``synthetic_ctx_id(authority, seed)``; pass it
    explicitly when a handler has to echo back the id it was asked for. The
    registry-assigned fields sit outside the ``content_hash`` preimage
    (RFC-ACDP-0001 §5.7), so splicing them on leaves the recomputed hash and
    the producer signature intact.
    """
    producer = mock_producer(authority, seed, slug)
    request = json.loads(
        producer.build_publish_request(
            title=title,
            context_type=context_type,
            visibility=visibility,
            **publish_kwargs,
        )
    )
    return {
        **request,
        "ctx_id": ctx_id or synthetic_ctx_id(authority, seed),
        "lineage_id": synthetic_lineage_id(seed),
        "origin_registry": authority,
        "created_at": created_at,
    }


PLAYGROUND_AUTHORITY = "registry-a.playground.local"

#: Every mock ``body`` fixture the offline suite serves, keyed by the module
#: that uses it. Adding a fixture here is what puts it under the
#: ``test_fixtures_are_valid_bodies`` guard — build new ones through
#: :func:`mock_body` and register them, rather than inlining a dict.
MOCK_BODIES: dict[str, dict[str, Any]] = {
    "test_client_auth.restricted_retrieve": mock_body(
        authority="r",
        seed="client-auth-restricted",
        title="restricted context",
        visibility="restricted",
        # visibility:restricted is invalid without a non-empty audience — the
        # SDK enforces it at build time (RFC-ACDP-0002 §3.2).
        audience=["did:web:r:agents:audience-member"],
    ),
    "test_client_v030.lifecycle_body": mock_body(
        authority="reg.test",
        seed="client-v030-lifecycle",
        title="t",
    ),
    "test_run_e2e_mocked.retrieve": mock_body(
        authority=PLAYGROUND_AUTHORITY,
        seed="e2e-mocked-retrieve",
        title="stub",
    ),
    "test_s6_restricted.retrieve": mock_body(
        authority=PLAYGROUND_AUTHORITY,
        seed="s6-restricted-context",
        title="Confidential — internal margin analysis",
        context_type="analysis",
        visibility="restricted",
        slug="confidant-producer",
        audience=[f"did:web:{PLAYGROUND_AUTHORITY}:agents:audience-member"],
    ),
}
