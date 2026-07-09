"""Tests for acdp_client.signing — the producer-algorithm abstraction."""

from __future__ import annotations

import json

import pytest

from acdp import AcdpProducer, AcdpVerifier
from acdp_client.signing import (
    ALG_ED25519,
    ALG_P256,
    is_p256,
    producer_algorithm,
    public_key_material,
    verify_signature,
)

try:
    from acdp import AcdpP256Producer

    HAS_P256 = True
except ImportError:  # pragma: no cover
    HAS_P256 = False

p256_only = pytest.mark.skipif(not HAS_P256, reason="SDK lacks AcdpP256Producer")

_DID = "did:web:registry-a.playground.local:agents:t"
_KID = f"{_DID}#key-1"


def _ed25519():
    return AcdpProducer.from_seed(bytes(range(32)), _DID, _KID)


def _p256():
    return AcdpP256Producer.from_seed(bytes(31) + bytes([1]), _DID, _KID)


def test_ed25519_algorithm_detection():
    p = _ed25519()
    assert producer_algorithm(p) == ALG_ED25519
    assert not is_p256(p)
    assert public_key_material(p) == p.public_key_b64


@p256_only
def test_p256_algorithm_detection():
    p = _p256()
    assert producer_algorithm(p) == ALG_P256
    assert is_p256(p)
    assert public_key_material(p) == p.public_key_sec1_b64


def test_verify_signature_ed25519_round_trip():
    p = _ed25519()
    raw = p.build_publish_request(title="t", context_type="data_snapshot")
    req = json.loads(raw)
    assert verify_signature(
        ALG_ED25519, p.public_key_b64, req["signature"]["value"], req["content_hash"]
    )


@p256_only
def test_verify_signature_p256_round_trip():
    p = _p256()
    raw = p.build_publish_request(title="t", context_type="analysis")
    req = json.loads(raw)
    assert req["signature"]["algorithm"] == ALG_P256
    assert verify_signature(
        ALG_P256, p.public_key_sec1_b64, req["signature"]["value"], req["content_hash"]
    )


@p256_only
def test_cross_algorithm_verify_fails():
    """A P-256 signature must not verify under the Ed25519 verifier."""
    p = _p256()
    req = json.loads(p.build_publish_request(title="t", context_type="analysis"))
    # Wrong key material/algorithm combo → SDK raises (returns non-True).
    with pytest.raises(Exception):
        AcdpVerifier.verify_signature(
            p.public_key_sec1_b64, req["signature"]["value"], req["content_hash"]
        )


def test_unknown_algorithm_raises():
    with pytest.raises(ValueError):
        verify_signature("rsa-pss", "x", "y", "z")
