"""Receipt + registry-DID helpers for the ACDP 0.2 trust scenarios.

These compose **only** ``acdp`` SDK primitives — JCS canonicalization
(:class:`AcdpCanonicalizer`) and Ed25519 signing
(:meth:`AcdpProducer.sign_challenge`) — so the playground never grows a
second implementation of the receipt preimage, the signature, or DID-document
key resolution (the delegation boundary in CLAUDE.md). They exist so a
scenario can *mint* a registry receipt offline (the live registry only ever
serves its current key, so the historical-key path is impossible to observe
without minting) and resolve a registry's receipt key through the
RFC-ACDP-0010 §9 lifecycle the SDK now models.
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
    canonical = AcdpCanonicalizer.canonicalize(json.dumps(receipt))
    preimage = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    receipt["signature"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": signer.sign_challenge(preimage),
    }
    return receipt


__all__ = ["did_document", "ed25519_jwk_vm", "mint_receipt"]
