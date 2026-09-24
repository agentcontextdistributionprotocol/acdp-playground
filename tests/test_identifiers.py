"""Tests for origin_registry / authority identifier hygiene, plus the
synthetic-identifier minter and a repo-wide sweep for non-conformant
``ctx_id`` literals.

The sweep is the part with teeth. The playground is a conformance harness
whose own fixtures were not conformant: ids like ``acdp://r/1`` or
``acdp://reg/ctx-3`` are shapes no registry could ever assign, and the SDK
only began parsing them strictly in 0.14.x — so they sat green for releases.
Anything the sweep finds must either satisfy the real grammar — a lowercase
DNS authority followed by a v4 UUID — or be named in one of the two
allowlists below, with a reason.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from acdp_client.identifiers import (
    is_conformant_ctx_id,
    is_valid_authority,
    synthetic_ctx_id,
    synthetic_lineage_id,
    validate_origin_registry,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Trees the literal sweep reads. ``acdp_client/`` is excluded on purpose: its
#: five occurrences are all scheme constants, grammar docstrings, or the
#: argument to a ``removeprefix`` — none of them a fixture.
SWEEP_ROOTS = ("playground", "tests", "scripts", "docs")

#: Text files worth reading in those trees.
SWEEP_SUFFIXES = frozenset({".py", ".md", ".json", ".yaml", ".yml", ".toml", ".txt", ".html"})

#: The ctx_id scheme, assembled rather than spelled — otherwise the sweep
#: would match its own regex source and this file would have to allowlist it.
_SCHEME = "acdp" + "://"

#: Every scheme-prefixed run in a swept file, stopping at whitespace, quotes
#: and the usual code delimiters. Matches only when *something* follows the
#: scheme, so a bare ``removeprefix`` argument is not read as an identifier.
_LITERAL_RE = re.compile(re.escape(_SCHEME) + r"[^\s\"'`\\)\]},;]+")

# ── The allowlist ────────────────────────────────────────────────────────────
#
# Two categories, and nothing else. An entry is a standing claim that the
# string is *supposed* to be non-conformant; each one names why.

#: Strings that are deliberately malformed because a test asserts they are
#: **rejected**. Laundering a real mistake through this category is blocked by
#: ``test_intentionally_malformed_allowlist_entries_are_actually_malformed``,
#: which re-checks that every entry genuinely fails the grammar.
INTENTIONALLY_MALFORMED: dict[str, str] = {
    "acdp://r/1": (
        "negative fixture: the pre-0.14 shape this phase swept out — no UUID at "
        "all. Kept here so is_conformant_ctx_id is tested against the exact "
        "string the repo used to ship."
    ),
    "acdp://reg/ctx-3": (
        "negative fixture: the mocked registry's old ctx_id minter output "
        "(tests/test_scenarios_v2.py). It fed derived_from, which 0.14.1 "
        "CtxId::parses — the second break vector this phase closes."
    ),
    "acdp://registry-a.playground.local/11111111-1111-1111-1111-111111111111": (
        "negative fixture: the old s23 receipt ctx_id. Well-formed 8-4-4-4-12 "
        "hex but version nibble '1', so CtxId::parse rejects it — the failure "
        "mode a naive 'looks like a UUID' check would miss."
    ),
    "acdp://registry-a.playground.local/00000000-0000-4000-c000-000000000000": (
        "negative fixture: correct version nibble, variant nibble 'c'. Pins the "
        "variant half of the grammar independently of the version half."
    ),
    "acdp://Registry-A.Playground.Local/00000000-0000-4000-8000-000000000000": (
        "negative fixture: uppercase authority. CtxId::parse requires a lowercase DNS authority."
    ),
    "acdp://registry-a.playground.local:8443/00000000-0000-4000-8000-000000000000": (
        "negative fixture: authority carrying a port, the RFC-ACDP-0002 §3.1 "
        "wire-convention violation acdp_client.identifiers exists to catch."
    ),
    "acdp://registry-a.playground.local/00000000-0000-4000-8000-00000000000G": (
        "negative fixture: non-hex character in the UUID."
    ),
    "acdp://registry-a.playground.local": ("negative fixture: authority with no '/<uuid>' at all."),
}

#: Strings that are never parsed as identifiers by anything — so their shape
#: carries no contract, and rewriting them would be churn.
NOT_AN_ID_INPUT: dict[str, str] = {
    "acdp://r/1": (
        "scripts/smoke_test.py:265,366 — inside *webhook payload bytes* "
        "(_check_webhook_signature / forward_webhook). Those bytes are "
        "HMAC-signed and relayed verbatim; nothing CtxId::parses them, and "
        "changing them would only re-baseline a signature fixture."
    ),
    "acdp://...": (
        "docs/http-api.md:116 — an elided sample SSE line, alongside "
        '"9f1c..." and "did:web:...". A documentation ellipsis, not a value.'
    ),
    "acdp://registry-a.playground.local/<uuid>": (
        "docs/http-api.md:154 — a grammar template describing the ctx_id form "
        "to a reader. Substituting a concrete UUID would make the docs less "
        "clear, not more correct."
    ),
}

#: Flattened for the sweep. ``acdp://r/1`` is in both categories (it is the
#: webhook-payload string *and* a negative fixture), which is fine — the sweep
#: only asks whether a literal is accounted for.
_ALLOWED = frozenset(INTENTIONALLY_MALFORMED) | frozenset(NOT_AN_ID_INPUT)


def _swept_files() -> list[Path]:
    files: list[Path] = []
    for root in SWEEP_ROOTS:
        for path in sorted((REPO_ROOT / root).rglob("*")):
            if path.is_file() and path.suffix in SWEEP_SUFFIXES:
                files.append(path)
    return files


# ── authority hygiene (RFC-ACDP-0002 §3.1) ───────────────────────────────────


@pytest.mark.parametrize(
    "host",
    [
        "registry-a.playground.local",
        "registry.example.com",
        "a.b.c.d.example",
        "x1.example",
    ],
)
def test_valid_authorities(host):
    assert is_valid_authority(host) is True
    validate_origin_registry(host)  # no raise


@pytest.mark.parametrize(
    "host",
    [
        "did:web:registry.example.com",  # DID form
        "registry.example.com:8443",  # port
        "https://registry.example.com",  # scheme
        "Registry.Example.Com",  # uppercase
        "registry.example.com.",  # trailing dot
        "registry..example",  # empty label
        "-bad.example",  # leading hyphen
        "bad-.example",  # trailing hyphen
        "",  # empty
    ],
)
def test_invalid_authorities(host):
    assert is_valid_authority(host) is False
    with pytest.raises(ValueError):
        validate_origin_registry(host)


# ── the synthetic minter ─────────────────────────────────────────────────────


def test_synthetic_ctx_id_is_v4_shaped():
    """Every minted id satisfies the grammar CtxId::parse enforces."""
    for seed in ("x", "", "s23-tamper-victim", "🙂", "a" * 500):
        ctx_id = synthetic_ctx_id("registry-a.playground.local", seed)
        assert is_conformant_ctx_id(ctx_id), ctx_id
        uuid_str = ctx_id.rsplit("/", 1)[1]
        assert uuid_str[14] == "4", f"version nibble: {uuid_str}"
        assert uuid_str[19] in "89ab", f"variant nibble: {uuid_str}"


def test_synthetic_ctx_id_entropy_is_not_truncated():
    """Distinct seeds must differ *beyond* the first hex group.

    The pattern this replaced was ``f"{run_id[:8]}-aaaa-aaaa-aaaa-…"``: 24 of
    the 32 hex digits were constant, so the id was really an 8-character
    namespace wearing a UUID costume.
    """
    tails = {synthetic_ctx_id("reg.test", f"seed-{n}").rsplit("/", 1)[1][9:] for n in range(64)}
    assert len(tails) == 64


def test_synthetic_ctx_id_is_deterministic():
    """Same value twice in-process **and** in a fresh interpreter."""
    expected = synthetic_ctx_id("registry-a.playground.local", "x")
    assert synthetic_ctx_id("registry-a.playground.local", "x") == expected

    # A separate process: catches any accidental dependence on per-process
    # state (PYTHONHASHSEED, a module-level RNG, an id() or time source).
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from acdp_client.identifiers import synthetic_ctx_id; "
                "print(synthetic_ctx_id('registry-a.playground.local', 'x'))"
            ),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == expected


def test_synthetic_ctx_id_rejects_a_bad_authority():
    for authority in ("Registry-A.Playground.Local", "reg.test:8443", "did:web:reg", ""):
        with pytest.raises(ValueError, match="authority"):
            synthetic_ctx_id(authority, "x")


def test_synthetic_ctx_id_varies_with_authority():
    a = synthetic_ctx_id("registry-a.playground.local", "shared-seed")
    b = synthetic_ctx_id("registry-b.playground.local", "shared-seed")
    assert a != b


def test_synthetic_lineage_id_form():
    """``lin:sha256:<64-lowercase-hex>`` — never ctx-shaped.

    s27 used to mint a *ctx-shaped* lineage_id, which Pydantic happily
    carried and the RFC does not permit.
    """
    lineage_id = synthetic_lineage_id("x")
    assert re.fullmatch(r"lin:sha256:[0-9a-f]{64}", lineage_id), lineage_id
    assert not lineage_id.startswith("acdp://")
    assert synthetic_lineage_id("x") == lineage_id
    assert synthetic_lineage_id("y") != lineage_id


@pytest.mark.parametrize(
    "value",
    [
        "acdp://registry-a.playground.local/00000000-0000-4000-8000-000000000000",
        "acdp://reg/12345678-1234-4321-8123-123456781234",
        "acdp://a.b.c.example/ffffffff-ffff-4fff-bfff-ffffffffffff",
    ],
)
def test_is_conformant_ctx_id_accepts_valid_ids(value):
    assert is_conformant_ctx_id(value) is True


@pytest.mark.parametrize("value", sorted(INTENTIONALLY_MALFORMED))
def test_is_conformant_ctx_id_rejects_the_malformed_fixtures(value):
    assert is_conformant_ctx_id(value) is False


def test_is_conformant_ctx_id_rejects_non_strings():
    for value in (None, 12345, b"a-bytes-identifier", ["a", "list"]):
        assert is_conformant_ctx_id(value) is False  # type: ignore[arg-type]


# ── the repo sweep ───────────────────────────────────────────────────────────


def test_no_nonconformant_ctx_id_literals_in_repo():
    """Every scheme-prefixed literal is conformant, or allowlisted with a reason."""
    files = _swept_files()
    assert len(files) > 50, f"the sweep only read {len(files)} files — it is not covering the repo"

    offenders: dict[str, set[str]] = {}
    seen = 0
    for path in files:
        for match in _LITERAL_RE.finditer(path.read_text(encoding="utf-8")):
            literal = match.group(0)
            seen += 1
            if literal in _ALLOWED or is_conformant_ctx_id(literal):
                continue
            offenders.setdefault(literal, set()).add(str(path.relative_to(REPO_ROOT)))

    assert seen, "the sweep matched no scheme literals at all — the regex is broken"
    assert not offenders, (
        "non-conformant ctx_id literals (want scheme + lowercase DNS authority "
        "+ v4 UUID): "
        + ", ".join(f"{k!r} in {', '.join(sorted(v))}" for k, v in sorted(offenders.items()))
        + ". Mint them with acdp_client.identifiers.synthetic_ctx_id, or add an "
        "allowlist entry to tests/test_identifiers.py saying why it must stay."
    )


def test_no_acdp_literals_in_the_scenario_catalog():
    """The catalog mints ids; it never spells them.

    Even a *conformant* hand-written literal in a scenario is a future drift
    site, so the catalog holds none at all.
    """
    catalog = REPO_ROOT / "playground" / "scenarios" / "catalog"
    found = {
        str(path.relative_to(REPO_ROOT)): _LITERAL_RE.findall(path.read_text(encoding="utf-8"))
        for path in sorted(catalog.glob("*.py"))
    }
    offenders = {k: v for k, v in found.items() if v}
    assert found, "no catalog files were read"
    assert not offenders, f"acdp:// literals left in the scenario catalog: {offenders}"


def test_intentionally_malformed_allowlist_entries_are_actually_malformed():
    """The allowlist cannot be used to launder a real mistake.

    Every ``INTENTIONALLY_MALFORMED`` entry must genuinely fail the grammar —
    if one starts passing, it was never a deliberate negative and belongs out
    of the list.
    """
    assert INTENTIONALLY_MALFORMED, "the category is empty — it is guarding nothing"
    for literal, reason in INTENTIONALLY_MALFORMED.items():
        assert not is_conformant_ctx_id(literal), (
            f"{literal!r} is allowlisted as intentionally malformed but is in fact "
            f"conformant — remove the entry rather than keeping a misleading one."
        )
        assert reason.strip(), f"{literal!r} has no stated reason"


def test_not_an_id_input_allowlist_entries_state_a_reason():
    assert NOT_AN_ID_INPUT, "the category is empty — it is guarding nothing"
    for literal, reason in NOT_AN_ID_INPUT.items():
        assert reason.strip(), f"{literal!r} has no stated reason"
