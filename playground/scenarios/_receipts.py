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
"""

from __future__ import annotations

import base64
import hashlib
import json

from acdp import AcdpCanonicalizer, AcdpProducer


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
]
