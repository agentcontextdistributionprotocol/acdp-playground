"""Emit deterministic agent identity material for pinning in registry config.

Usage:
    uv run python scripts/gen_keys.py [--algorithm ed25519|ecdsa-p256] \\
        registry-a.playground.local agent-alpha [agent-beta...]

For Ed25519 agents the output carries ``public_key_b64`` (the 44-char
base64 of the raw 32-byte key) — drop it into a registry
``[[playground.pinned_keys]]`` block.

For ECDSA-P256 agents the output carries ``public_key_sec1_b64`` (the
88-char base64 of the SEC1-uncompressed 65-byte key), the JWK, and a
ready-to-paste did:web ``verification_method`` so a real (non-pinned)
deployment can resolve the key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from acdp import AcdpProducer

try:
    from acdp import AcdpP256Producer
except ImportError:  # pragma: no cover
    AcdpP256Producer = None  # type: ignore[assignment, misc]


def _p256_seed(seed: bytes) -> bytes:
    """Re-hash until the digest is a valid P-256 scalar (see _factory)."""
    assert AcdpP256Producer is not None
    candidate = seed
    for _ in range(8):
        try:
            AcdpP256Producer.from_seed(
                candidate, "did:web:probe:agents:x", "did:web:probe:agents:x#k"
            )
            return candidate
        except ValueError:
            candidate = hashlib.sha256(candidate).digest()
    raise SystemExit("could not derive a valid P-256 scalar from seed")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument(
        "--algorithm",
        choices=("ed25519", "ecdsa-p256"),
        default="ed25519",
        help="signature algorithm for the generated identities",
    )
    p.add_argument("authority", help="registry authority (did:web host)")
    p.add_argument("slugs", nargs="+", help="agent slug(s)")
    args = p.parse_args(argv)

    if args.algorithm == "ecdsa-p256" and AcdpP256Producer is None:
        raise SystemExit(
            "ecdsa-p256 requested but the installed acdp SDK lacks "
            "AcdpP256Producer — rebuild acdp-py (maturin)."
        )

    out = []
    for slug in args.slugs:
        # Deterministic from authority + slug; replace with random for prod.
        seed = hashlib.sha256(f"{args.authority}:{slug}".encode()).digest()
        did = f"did:web:{args.authority}:agents:{slug}"
        key_id = f"{did}#key-1"
        if args.algorithm == "ecdsa-p256":
            seed = _p256_seed(seed)
            producer = AcdpP256Producer.from_seed(seed, did, key_id)
            out.append(
                {
                    "slug": slug,
                    "agent_did": did,
                    "key_id": key_id,
                    "algorithm": "ecdsa-p256",
                    "public_key_sec1_b64": producer.public_key_sec1_b64,
                    "public_key_jwk": json.loads(producer.public_key_jwk),
                    "verification_method": json.loads(
                        producer.did_verification_method(key_id, did)
                    ),
                    "seed_hex": seed.hex(),
                }
            )
        else:
            producer = AcdpProducer.from_seed(seed, did, key_id)
            out.append(
                {
                    "slug": slug,
                    "agent_did": did,
                    "key_id": key_id,
                    "algorithm": "ed25519",
                    "public_key_b64": producer.public_key_b64,
                    "seed_hex": seed.hex(),
                }
            )
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
