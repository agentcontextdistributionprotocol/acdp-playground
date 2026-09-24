"""Identifier-hygiene checks (RFC-ACDP-0002 §3.1).

``origin_registry`` (and a registry's own authority) is a **bare DNS
hostname** — lowercase ASCII LDH labels, no port, no scheme, no ``did:``
prefix. The wire-convention tightening in the RFC (commit ``05bab36``,
``body-001``/``body-002`` fixtures) makes this normative because a
``host:port`` or ``did:web:host`` value changes the ``content_hash``
preimage and breaks federation routing.

These helpers let the playground assert that a retrieved body's
``origin_registry`` is well-formed before trusting it for cross-registry
resolution.

The module also owns the playground's **synthetic identifier minter**
(:func:`synthetic_ctx_id` / :func:`synthetic_lineage_id`). Scenarios, mocks
and smoke checks need ``ctx_id``/``lineage_id`` values that no real registry
assigned, and hand-written ones drift out of grammar silently — the SDK only
started parsing them strictly in 0.14.x. Minting them in one place keeps every
fixture conformant *and* reproducible.
"""

from __future__ import annotations

import hashlib
import re
import uuid

# One DNS label: LDH (letters/digits/hyphen), no leading/trailing hyphen,
# 1–63 chars. Hostnames are lowercased before matching.
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# The ``ctx_id`` scheme prefix (RFC-ACDP-0002 §3.1).
_CTX_ID_SCHEME = "acdp://"

# The UUID half of a ``ctx_id``: 8-4-4-4-12 **lowercase** hex with version
# nibble ``4`` and variant nibble in ``{8,9,a,b}``. Mirrors the SDK's own
# ``is_valid_uuid_v4`` (acdp-rs/crates/acdp-primitives/src/primitives.rs:490-512)
# so fixtures can be checked without importing the Rust parser.
_UUID_V4 = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")

# ``lineage_id`` form: ``lin:sha256:<64-lowercase-hex>`` (primitives.rs:74-89).
_LINEAGE_ID_PREFIX = "lin:sha256:"

# The reserved tenant sentinel — the silent column default for untenanted
# rows on both the registry and the control plane.
RESERVED_TENANT = "default"


def is_valid_authority(host: str) -> bool:
    """True iff ``host`` is a bare DNS hostname (no port/scheme/DID/uppercase).

    Validation is strict and case-sensitive: ``Registry.Example`` is
    rejected because authorities are minted lowercase. Trailing dots,
    ports, schemes, and ``did:`` forms are all rejected.
    """
    if not host or host != host.lower():
        return False
    if ":" in host or "/" in host or host.startswith("did:"):
        return False
    if host.endswith(".") or ".." in host:
        return False
    if len(host) > 253:
        return False
    return all(_LABEL.match(label) for label in host.split("."))


def validate_origin_registry(value: str) -> None:
    """Raise ``ValueError`` unless ``value`` is a conformant authority."""
    if not is_valid_authority(value):
        raise ValueError(
            f"origin_registry must be a bare DNS hostname "
            f"(no port/scheme/did:/uppercase): {value!r}"
        )


def is_reserved_tenant(tenant: str | None) -> bool:
    """True iff ``tenant`` is the reserved ``default`` sentinel."""
    return tenant == RESERVED_TENANT


def reject_reserved_tenant(tenant: str | None) -> None:
    """Raise ``ValueError`` if ``tenant`` explicitly asserts the reserved sentinel.

    ``default`` is the silent column default for untenanted rows. Asserting it
    via ``X-Tenant-Id`` or a signed ``tenant`` claim would alias the entire
    untenanted bucket — a cross-boundary read/write. Both siblings now reject
    it server-side (registry ``reject_reserved_tenant``, acdp-registry-core
    ``c988ea4`` → 400 ``schema_violation``; control-plane ``AuthGuard``, #50 →
    403 ``not_authorized``). We mirror the rule client-side so a caller who
    sets ``tenant_id="default"`` fails fast locally with a clear message
    instead of a confusing server rejection. Untenanted access stays reachable
    only through the *absence* of an assertion (``None``), which passes through
    untouched.
    """
    if is_reserved_tenant(tenant):
        raise ValueError(
            f"{RESERVED_TENANT!r} is a reserved tenant sentinel and cannot be "
            "asserted via X-Tenant-Id or a token claim; omit the tenant "
            "entirely for untenanted access"
        )


def is_conformant_ctx_id(value: str) -> bool:
    """True iff ``value`` is a ``ctx_id`` the SDK's ``CtxId::parse`` accepts.

    Grammar (``acdp-common.schema.json#/$defs/ctx_id``, mirrored from
    ``acdp-rs/crates/acdp-primitives/src/primitives.rs:26-50``)::

        acdp://<lowercase-DNS-authority>/<v4-uuid>

    with the UUID's version nibble equal to ``4`` and its variant nibble one
    of ``8``/``9``/``a``/``b``. This is a *local* re-implementation on
    purpose: fixture sweeps need to classify strings that never reach the
    SDK, and 0.8.3 has no binding that parses a bare ``ctx_id``. It is the
    one deliberate exception to CLAUDE.md's delegation rule, and it is kept
    honest by staying a strict mirror of the Rust parser above.
    """
    if not isinstance(value, str) or not value.startswith(_CTX_ID_SCHEME):
        return False
    authority, sep, uuid_str = value[len(_CTX_ID_SCHEME) :].partition("/")
    if not sep:
        return False
    return is_valid_authority(authority) and _UUID_V4.match(uuid_str) is not None


def synthetic_ctx_id(authority: str, seed: str) -> str:
    """Mint a deterministic, conformant synthetic ``ctx_id`` from ``seed``.

    The UUID half is the first 16 bytes of ``sha256(seed)`` with the version
    and variant nibbles stamped — exactly what ``uuid.UUID(bytes=...,
    version=4)`` does — so the result is a structurally valid v4 that is
    nonetheless reproducible from the seed, in-process and across processes.

    Determinism is the point: :meth:`RunSpec.agent_seed` already makes runs
    reproducible, several scenarios compare ids across steps, and a
    ``uuid4()`` fixture makes a failure unrepeatable. All 122 free bits come
    from the digest, so two seeds collide only by sha256 collision — note the
    contrast with the pattern this replaced, which varied only the first 8 hex
    characters and left the remaining 24 constant.

    Raises ``ValueError`` if ``authority`` is not a bare lowercase DNS
    hostname, since a ctx_id built on a bad authority fails ``CtxId::parse``
    just as surely as a bad UUID does.
    """
    if not is_valid_authority(authority):
        raise ValueError(
            f"ctx_id authority must be a bare lowercase DNS hostname "
            f"(no port/scheme/did:/uppercase): {authority!r}"
        )
    raw = bytearray(hashlib.sha256(seed.encode("utf-8")).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40  # version nibble → 4
    raw[8] = (raw[8] & 0x3F) | 0x80  # variant nibble → 8..b
    return f"{_CTX_ID_SCHEME}{authority}/{uuid.UUID(bytes=bytes(raw))}"


def synthetic_lineage_id(seed: str) -> str:
    """Mint a deterministic, conformant synthetic ``lineage_id`` from ``seed``.

    Emits the ``lin:sha256:<64-lowercase-hex>`` form the rest of the repo
    already uses for lineage ids. A ``lineage_id`` is *not* ctx-shaped: a
    receipt carrying an ``acdp://…`` lineage_id is malformed even though it
    round-trips through Pydantic.
    """
    return _LINEAGE_ID_PREFIX + hashlib.sha256(seed.encode("utf-8")).hexdigest()


__all__ = [
    "RESERVED_TENANT",
    "is_conformant_ctx_id",
    "is_reserved_tenant",
    "is_valid_authority",
    "reject_reserved_tenant",
    "synthetic_ctx_id",
    "synthetic_lineage_id",
    "validate_origin_registry",
]
