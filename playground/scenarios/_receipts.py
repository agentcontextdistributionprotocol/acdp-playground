"""Receipt + registry-DID helpers for the ACDP 0.2/0.3 trust scenarios.

These compose **only** ``acdp`` SDK primitives — JCS canonicalization
(:class:`AcdpCanonicalizer`) and Ed25519 signing
(:meth:`AcdpProducer.sign_challenge`) — so the playground never grows a
second implementation of the receipt preimage, the signature, or DID-document
key resolution (the delegation boundary in CLAUDE.md). They exist so a
scenario can *mint* a registry receipt offline (the live registry only ever
serves its current key, so the historical-key path is impossible to observe
without minting) and resolve a registry's receipt key through the
RFC-ACDP-0010 §9 lifecycle the SDK now models.

The ACDP 0.3.0 artifacts — lifecycle events (RFC-ACDP-0013 §5), lineage-head
receipts (RFC-ACDP-0011 §5) and transparency-log checkpoints (RFC-ACDP-0012
§7) — all reuse the RFC-ACDP-0010 §5 signing construction verbatim: SHA-256
over the JCS form of the object minus ``signature``, signed as the ASCII
``"sha256:<hex>"`` string. The mint helpers below share :func:`_signed` so
that construction exists exactly once here too.

:func:`synthesize_retrieval_body` extends the same position to the *served*
half of a retrieval. A receipt attests a body, so a scenario that mints one
needs the body it attests — and a registry assigns exactly four fields on it:
``ctx_id``, ``lineage_id``, ``origin_registry`` and ``created_at``. Only three
of those are *absent* from a `PublishRequest`; ``lineage_id`` exists on both,
because a v2+ supersede request legitimately carries it for the registry to
verify against (``acdp-rs/crates/acdp-types/src/publish.rs:72-78``), which is
why the helper merges-or-verifies that one rather than refusing it. It overlays
those onto a **real** SDK-built publish request and never fabricates the signed
half, so the producer signature and ``content_hash`` stay the SDK's, and the
body schema still has exactly one implementation — the Rust one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from acdp import AcdpCanonicalizer, AcdpProducer, AcdpVerifier

#: Canonical millisecond-precision RFC 3339 UTC — exactly three fractional
#: digits and a literal ``Z`` (RFC-ACDP-0010 §8 step 6). ``RegistryReceipt``
#: serializes ``created_at`` through ``ms_rfc3339``
#: (``acdp-rs/crates/acdp-types/src/receipt.rs:177``), so any other byte form
#: — ``+00:00``, microseconds, a bare local time — changes the receipt
#: preimage even though ``Body``'s own deserializer accepts it permissively.
_MS_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")

#: The three ``Body`` fields a ``PublishRequest`` can never legitimately carry
#: (``acdp-rs/crates/acdp-types/src/body.rs:20-41`` minus ``publish.rs:26-64``).
#: ``lineage_id`` is the deliberate fourth — see :func:`synthesize_retrieval_body`.
_REGISTRY_ONLY_FIELDS = ("ctx_id", "origin_registry", "created_at")

#: ``AcdpError::KeyResolution``'s Display prefix
#: (``acdp-rs/crates/acdp-primitives/src/error.rs:237``). ``verify_body_offline``
#: raises it for any non-``did:key`` producer
#: (``crates/acdp-verify/src/lib.rs:294-300``) — a limitation of offline
#: verification, not a defect in the body.
_OFFLINE_KEY_RESOLUTION = "key resolution failed:"


def ed25519_jwk_vm(key_id: str, controller: str, public_key_b64: str) -> dict:
    """An ``Ed25519`` verification method in ``publicKeyJwk`` (OKP) form.

    The SDK's DID-document parser accepts ``publicKeyJwk`` (OKP/Ed25519) or
    ``publicKeyMultibase``; the JWK form is the one the playground can build
    from a producer's raw public key without a multibase/multicodec encoder.
    """
    x = base64.urlsafe_b64encode(base64.b64decode(public_key_b64)).rstrip(b"=").decode()
    return {
        "id": key_id,
        "type": "JsonWebKey2020",
        "controller": controller,
        "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
    }


def did_document(
    did: str,
    *,
    current: list[dict],
    retired: list[dict] | None = None,
) -> str:
    """Serialize a DID document expressing the RFC-ACDP-0010 §9 key lifecycle.

    ``current`` keys land in both ``verificationMethod`` and
    ``assertionMethod`` (still authorized to sign); ``retired`` keys land in
    ``verificationMethod`` only — a rotated key stays resolvable (so historical
    signatures/receipts still verify) but is no longer authorized to produce
    new ones. Applies to a registry's receipt keys and a producer's signing
    keys alike. Returns the JSON string ready for :meth:`AcdpDidDocument.parse`.
    """
    vms = [*(retired or []), *current]
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": vms,
        "assertionMethod": [vm["id"] for vm in current],
    }
    return json.dumps(doc)


def _signed(obj: dict, signer: AcdpProducer, key_id: str) -> dict:
    """Attach the RFC-ACDP-0010 §5 signature to ``obj`` (shared by receipts,
    lifecycle events, lineage-head receipts and log checkpoints).

    The preimage is SHA-256 over the JCS canonical form of the object
    **minus** the ``signature`` member; the signature is Ed25519 over the
    ASCII bytes of the full ``"sha256:<hex>"`` string (never the raw digest).
    """
    canonical = AcdpCanonicalizer.canonicalize(json.dumps(obj))
    preimage = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    return {
        **obj,
        "signature": {
            "algorithm": "ed25519",
            "key_id": key_id,
            "value": signer.sign_challenge(preimage),
        },
    }


def synthesize_retrieval_body(
    publish_request_json: str,
    *,
    ctx_id: str,
    lineage_id: str,
    origin_registry: str,
    created_at: str,
) -> dict[str, Any]:
    """Model the ``body`` a registry would serve for ``publish_request_json``.

    ``publish_request_json`` is the wire JSON a producer built —
    :meth:`AcdpProducer.build_publish_request` or
    :meth:`~AcdpProducer.build_supersede_request` — and the result is the
    object a retrieval returns as ``full["body"]``: the same producer content,
    the same ``content_hash``, the same signature, plus the identity a registry
    assigns on acceptance. Those registry-assigned fields sit outside the
    ``content_hash`` preimage (RFC-ACDP-0001 §5.7), so splicing them on leaves
    the producer's integrity half untouched — which is why this is an overlay
    and never a hand-built dict.

    ``ctx_id``, ``origin_registry`` and ``created_at`` are overlaid
    unconditionally, and a request that already carries one raises
    :class:`ValueError`: a ``PublishRequest`` has no such field
    (``acdp-rs/crates/acdp-types/src/publish.rs:26-64``), so its appearance
    means the schema moved and a silent overwrite would hide that.

    ``lineage_id`` is **merge-or-verify**, because it is the one field on both
    types: ``PublishRequest.lineage_id`` is the optional supersession
    self-verification value (``publish.rs:72-78`` — v1 publications MUST NOT
    include it, v2+ MAY). Absent, it is set; present, it must *equal*
    ``lineage_id`` — a conflict means the caller is splicing a supersede into
    the wrong lineage, which is an authoring bug, not a field to silently pick
    a winner for.

    ``created_at`` must be canonical millisecond-precision RFC 3339 UTC
    (``…SS.mmmZ``). ``Body``'s deserializer accepts ``+00:00`` and microsecond
    precision, but a receipt minted against such a body fails RFC-ACDP-0010 §8
    step 6 on byte form alone, so the check happens here where the error can
    still name the authoring mistake.

    Before returning, the result round-trips through the SDK, so a caller can
    never receive a body the SDK would reject:
    :meth:`AcdpVerifier.verify_body_offline` deserializes into ``Body`` proper
    (``acdp-rs/bindings/acdp-py/src/verifier.rs:236``) and therefore fails on a
    missing or malformed required field, and
    :meth:`~AcdpVerifier.verify_content_hash` recomputes the digest over the
    overlaid object — a true invariant, not a tautology, since hash coverage
    excludes all four overlaid fields. For a ``did:web`` producer
    ``verify_body_offline`` can only get as far as key resolution
    (``crates/acdp-verify/src/lib.rs:294-300``); that one ``RuntimeError`` is
    tolerated, every other SDK rejection propagates.
    """
    if not _MS_RFC3339.fullmatch(created_at):
        raise ValueError(
            "created_at must be canonical millisecond-precision RFC 3339 UTC "
            f"(YYYY-MM-DDTHH:MM:SS.mmmZ, exactly three fractional digits and a "
            f"literal 'Z'): {created_at!r}"
        )

    request: dict[str, Any] = json.loads(publish_request_json)

    collisions = [field for field in _REGISTRY_ONLY_FIELDS if field in request]
    if collisions:
        raise ValueError(
            f"publish request already carries registry-assigned field(s) "
            f"{collisions} — a PublishRequest has none of them, so overlaying "
            f"would mask a schema change rather than model a registry"
        )

    declared = request.get("lineage_id")
    if declared is not None and declared != lineage_id:
        raise ValueError(
            f"publish request declares lineage_id {declared!r} but the caller "
            f"passed {lineage_id!r}; a v2+ supersede's self-verification value "
            f"must equal the lineage it is served under"
        )

    body = {
        **request,
        "ctx_id": ctx_id,
        "lineage_id": lineage_id,
        "origin_registry": origin_registry,
        "created_at": created_at,
    }

    body_json = json.dumps(body)
    try:
        AcdpVerifier.verify_body_offline(body_json)
    except RuntimeError as exc:
        did_key = str(request.get("agent_id", "")).startswith("did:key:")
        if did_key or _OFFLINE_KEY_RESOLUTION not in str(exc):
            raise
    AcdpVerifier.verify_content_hash(body_json, body["content_hash"])
    return body


def mint_receipt(
    signer: AcdpProducer,
    key_id: str,
    *,
    registry_did: str,
    ctx_id: str,
    lineage_id: str,
    origin_registry: str,
    created_at: str,
    content_hash: str,
    key_fingerprint: str,
) -> dict:
    """Mint a registry-signed receipt the way a receipts-profile registry does.

    The preimage is SHA-256 over the JCS canonical form of the receipt
    **minus** the ``signature`` field (RFC-ACDP-0010 §8); the registry signs
    that ``sha256:<hex>`` string with its Ed25519 receipt key. We reuse the
    SDK's canonicalizer and signer so the result verifies under
    :meth:`AcdpVerifier.verify_receipt` byte-for-byte.
    """
    receipt = {
        "registry_did": registry_did,
        "ctx_id": ctx_id,
        "lineage_id": lineage_id,
        "origin_registry": origin_registry,
        "created_at": created_at,
        "content_hash": content_hash,
        "key_fingerprint": key_fingerprint,
    }
    return _signed(receipt, signer, key_id)


def mint_lifecycle_event(
    signer: AcdpProducer,
    *,
    event_id: str,
    ctx_id: str,
    event_type: str,
    occurred_at: str,
    reason: str | None = None,
    key_id: str | None = None,
) -> dict:
    """Mint a signed lifecycle event (RFC-ACDP-0013 §4/§5).

    The actor is the signer's own DID (`signer.agent_did`) and the signature
    ``key_id`` defaults to the signer's key — §5 requires the key_id's DID
    portion to equal ``actor``. ``occurred_at`` must be canonical
    millisecond-precision RFC 3339 UTC (``YYYY-MM-DDTHH:MM:SS.mmmZ``). The
    result verifies under :meth:`AcdpVerifier.verify_lifecycle_event` and is
    the exact request body the registry's retract/republish endpoints expect.
    """
    event = {
        "event_id": event_id,
        "ctx_id": ctx_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor": signer.agent_did,
    }
    if reason is not None:
        event["reason"] = reason
    return _signed(event, signer, key_id or signer.key_id)


def mint_lineage_head_receipt(
    signer: AcdpProducer,
    key_id: str,
    *,
    registry_did: str,
    lineage_id: str,
    head_ctx_id: str,
    head_version: int,
    head_status: str,
    as_of: str,
) -> dict:
    """Mint a lineage-head receipt (RFC-ACDP-0011 §5) the way a
    head-receipts-profile registry does. Verifies under
    :meth:`AcdpVerifier.verify_lineage_head_receipt`."""
    receipt = {
        "receipt_version": "acdp-lhr/1",
        "registry_did": registry_did,
        "lineage_id": lineage_id,
        "head_ctx_id": head_ctx_id,
        "head_version": head_version,
        "head_status": head_status,
        "as_of": as_of,
    }
    return _signed(receipt, signer, key_id)


def mint_log_checkpoint(
    signer: AcdpProducer,
    key_id: str,
    *,
    log_id: str,
    tree_size: int,
    root_hash: str,
    timestamp: str,
) -> dict:
    """Mint a transparency-log checkpoint (RFC-ACDP-0012 §7) — a signed tree
    head. Verifies under :meth:`AcdpVerifier.verify_log_checkpoint`."""
    checkpoint = {
        "checkpoint_version": "acdp-log/1",
        "log_id": log_id,
        "tree_size": tree_size,
        "root_hash": root_hash,
        "timestamp": timestamp,
    }
    return _signed(checkpoint, signer, key_id)


__all__ = [
    "did_document",
    "ed25519_jwk_vm",
    "mint_lifecycle_event",
    "mint_lineage_head_receipt",
    "mint_log_checkpoint",
    "mint_receipt",
    "synthesize_retrieval_body",
]
