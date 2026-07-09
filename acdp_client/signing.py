"""Producer abstraction over the two acdp-py signer classes.

The SDK ships two structurally-identical producer types:

* :class:`acdp.AcdpProducer`      — Ed25519 signatures (``ed25519``)
* :class:`acdp.AcdpP256Producer`  — ECDSA-P256 signatures (``ecdsa-p256``)

Both expose the same duck-typed surface the playground relies on
(``agent_did``, ``key_id``, ``sign_challenge``, ``build_publish_request``,
``build_supersede_request``), so the rest of the code treats them
interchangeably through the :data:`Producer` union and only branches on
the wire algorithm when it has to — namely when minting a registry token
(``POST /auth/token`` carries an explicit ``algorithm`` field) and when
verifying a signature (Ed25519 vs P-256 verify paths differ).

Keeping the branch in one place avoids scattering ``isinstance`` checks
and keeps the ``algorithm`` string the single source of truth.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:  # pragma: no cover - typing only
    from acdp import AcdpP256Producer, AcdpProducer

    Producer = Union[AcdpProducer, AcdpP256Producer]
else:  # runtime: the SDK classes are concrete, duck-typed
    Producer = object


# Wire algorithm identifiers per RFC-ACDP-0003 / registry /auth/token.
ALG_ED25519 = "ed25519"
ALG_P256 = "ecdsa-p256"

_P256_CLASS_NAMES = {"AcdpP256Producer", "PyAcdpP256Producer"}


def producer_algorithm(producer: "Producer") -> str:
    """Return the wire signature algorithm for ``producer``.

    Detected from the concrete SDK class name rather than ``isinstance``
    so the helper works even when only one producer class is importable
    (older SDK builds lacked ``AcdpP256Producer`` entirely).
    """
    name = type(producer).__name__
    if name in _P256_CLASS_NAMES:
        return ALG_P256
    return ALG_ED25519


def is_p256(producer: "Producer") -> bool:
    return producer_algorithm(producer) == ALG_P256


def public_key_material(producer: "Producer") -> str:
    """Return the producer's public key in the encoding its algorithm uses.

    * Ed25519 → raw 32-byte key, standard base64 (``public_key_b64``)
    * P-256   → SEC1-uncompressed 65-byte key, standard base64
      (``public_key_sec1_b64``)

    This is the value a verifier needs: pass it to
    :func:`verify_signature` alongside the algorithm.
    """
    if is_p256(producer):
        return producer.public_key_sec1_b64  # type: ignore[union-attr]
    return producer.public_key_b64  # type: ignore[union-attr]


def verify_signature(
    algorithm: str,
    public_key_material: str,
    signature_b64: str,
    content_hash: str,
) -> bool:
    """Verify a signature using the algorithm-appropriate SDK verifier.

    Raises ``ValueError`` for an unknown algorithm. The underlying SDK
    raises on a bad signature, so a return of ``True`` means verified.
    """
    from acdp import AcdpVerifier

    if algorithm == ALG_ED25519:
        return AcdpVerifier.verify_signature(public_key_material, signature_b64, content_hash)
    if algorithm == ALG_P256:
        return AcdpVerifier.verify_signature_p256(public_key_material, signature_b64, content_hash)
    raise ValueError(f"unknown signature algorithm: {algorithm!r}")
