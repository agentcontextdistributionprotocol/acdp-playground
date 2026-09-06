"""Validate JCS canonicalization against the RFC's can-011 vectors.

Canonicalization now runs in the Rust SDK and is exercised here through the
``acdp.AcdpCanonicalizer`` binding (``acdp-py`` 0.2.0) — the playground no
longer ships its own pure-Python JCS reference. The fixtures live in the
sibling RFC repo; the test loads them from ``ACDP_RFC_DIR`` (default
``../agentcontextdistributionprotocol``) and skips cleanly when absent.

The binding takes a JSON *string* (FFI convention) and re-canonicalizes its
numbers, so a vector value is round-tripped through ``json.dumps`` first; the
ECMAScript ``Number::toString`` rules (RFC 8785 §3.2.2.3) are asserted by
canonicalizing a bare-number document.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from acdp import AcdpCanonicalizer

_RFC_DIR = Path(os.environ.get("ACDP_RFC_DIR", "../agentcontextdistributionprotocol"))
_VECTORS = _RFC_DIR / "schemas" / "conformance" / "can-011-jcs-numeric-vectors.json"


def _canon(value) -> str:
    """Canonical form of a JSON value via the Rust binding."""
    return AcdpCanonicalizer.canonicalize(json.dumps(value))


def _canon_number(literal: str) -> str:
    """Canonical form of a bare-number JSON document (e.g. ``"1e21"``)."""
    return AcdpCanonicalizer.canonicalize(literal)


def _load_vectors():
    if not _VECTORS.exists():
        pytest.skip(f"RFC conformance vectors not found at {_VECTORS}")
    return json.loads(_VECTORS.read_text())["vectors"]


def test_can011_vectors_match():
    for vec in _load_vectors():
        got = _canon(vec["input"])
        want = vec["expected"]["canonical_form"]
        assert got == want, f"{vec['name']}: {got!r} != {want!r}"
        digest = hashlib.sha256(got.encode("utf-8")).hexdigest()
        assert digest == vec["expected"]["sha256_hex"], vec["name"]


def test_negative_zero_normalizes():
    assert _canon_number("-0.0") == "0"
    assert _canon_number("0.0") == "0"


def test_exponential_bands():
    assert _canon_number("1e21") == "1e+21"
    assert _canon_number("1e-7") == "1e-7"
    assert _canon_number("1e-6") == "0.000001"  # decimal band edge
    assert _canon_number("5e-9") == "5e-9"


def test_integer_exactness():
    assert _canon_number("9007199254740992") == "9007199254740992"  # 2**53
    assert _canon_number("100") == "100"
    assert _canon_number("-7") == "-7"


def test_trailing_zero_dropped():
    assert _canon_number("1.10") == "1.1"
    assert _canon_number("1.50") == "1.5"


def test_object_keys_sorted():
    assert AcdpCanonicalizer.canonicalize('{"b":1,"a":2}') == '{"a":2,"b":1}'


def test_content_hash_matches_manual_sha256():
    canon = AcdpCanonicalizer.canonicalize('{"b":1,"a":2}')
    digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    assert AcdpCanonicalizer.content_hash('{"b":1,"a":2}') == f"sha256:{digest}"


def test_rejects_non_json_number_tokens():
    # NaN / Infinity are not valid JSON tokens, so the binding rejects them.
    with pytest.raises(ValueError):
        _canon_number("NaN")
    with pytest.raises(ValueError):
        _canon_number("Infinity")
