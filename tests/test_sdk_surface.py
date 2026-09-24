"""Pin the `acdp` SDK surface this repo calls.

The playground's whole purpose is detecting drift against real binaries, yet its
one hard dependency — the `acdp` maturin/pyo3 wheel — had no drift detection at
all. Python has no compile step, so a renamed method or a new *required*
positional argument does not fail a build: it raises :class:`TypeError` at the
call site, at runtime, inside whichever scenario happens to run it. Scenarios
that assert a negative ("the SDK must reject this") used to score that
``TypeError`` as the rejection working, so the break could stay invisible.

This module is the local equivalent of the SDK's own
``bindings/interop/expected_surface.json``: a declarative table of every symbol
this repo calls, with the arity the repo was written against, asserted through
:func:`inspect.signature`. When it goes red on an SDK bump, it is telling you
exactly which call sites need revisiting.

**Updating it on an SDK bump.** Do *not* relax an entry to make the suite green.
Read the new signature, fix the call sites, and only then move the number — the
entry is a record of what the code was written against, and moving it without
touching the callers re-hides the break it exists to surface.

Arities count ``self`` for instance methods (``inspect.signature`` on the
unbound descriptor sees it), so ``AcdpProducer.sign_challenge`` is ``(2, 2)``:
``self`` plus ``signing_input``.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import acdp
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Directories swept by :func:`test_every_sdk_call_in_the_repo_is_registered`.
SOURCE_ROOTS = ("acdp_client", "playground", "tests", "scripts")

#: This file *is* the registry, and it names symbols (deliberately absent ones,
#: dunder lookups) that are not call sites — so it excludes itself from the sweep.
SWEEP_EXCLUDE = frozenset({Path(__file__).name})

#: ``"Class.method" -> (required_args, total_args)`` for every `acdp` callable
#: this repo invokes. Verified against `acdp==0.8.3`.
EXPECTED_SURFACE: dict[str, tuple[int, int]] = {
    # JCS canonicalization + content hashing (RFC-ACDP-0001 §5).
    "AcdpCanonicalizer.canonicalize": (1, 1),
    "AcdpCanonicalizer.content_hash": (1, 1),
    # DID documents + the RFC-ACDP-0010 §9 receipt-key lifecycle.
    "AcdpDidDocument.parse": (2, 2),
    "AcdpDidDocument.key_for_algorithm": (3, 3),
    "AcdpDidDocument.receipt_key_for_algorithm": (3, 3),
    # Transparency-log Merkle primitives (RFC-ACDP-0012).
    "AcdpMerkle.leaf_hash": (1, 1),
    "AcdpMerkle.root_hash": (1, 1),
    # Ed25519 producers.
    "AcdpProducer.from_seed": (3, 3),
    "AcdpProducer.from_seed_did_key": (1, 1),
    "AcdpProducer.build_publish_request": (3, 20),
    "AcdpProducer.build_supersede_request": (2, 16),
    "AcdpProducer.sign_challenge": (2, 2),
    "AcdpProducer.seed_bytes": (1, 1),
    # P-256 producers.
    "AcdpP256Producer.from_seed": (3, 3),
    "AcdpP256Producer.from_seed_did_key": (1, 1),
    "AcdpP256Producer.build_publish_request": (3, 20),
    "AcdpP256Producer.build_supersede_request": (2, 16),
    "AcdpP256Producer.sign_challenge": (2, 2),
    "AcdpP256Producer.did_verification_method": (3, 3),
    "AcdpP256Producer.seed_bytes": (1, 1),
    # SSRF classification (delegated wholesale; see CLAUDE.md).
    "AcdpSsrfPolicy.production": (0, 0),
    "AcdpSsrfPolicy.allow_test_loopback": (0, 0),
    "AcdpSsrfPolicy.check_url": (2, 2),
    "AcdpSsrfPolicy.check_ip": (2, 2),
    "AcdpSsrfPolicy.check_redirect_authority": (3, 3),
    # Verification.
    "AcdpVerifier.build_log_leaf": (1, 1),
    "AcdpVerifier.build_witness_cosignature": (4, 4),
    "AcdpVerifier.canonical_preimage": (1, 1),
    "AcdpVerifier.classify_under_revocation": (2, 3),
    "AcdpVerifier.evaluate_witness_quorum": (5, 6),
    "AcdpVerifier.explain_hash_mismatch": (2, 2),
    "AcdpVerifier.fingerprint_ed25519_b64": (1, 1),
    "AcdpVerifier.parse_key_revocation": (1, 2),
    "AcdpVerifier.verify_body_offline": (1, 1),
    "AcdpVerifier.verify_content_hash": (2, 2),
    "AcdpVerifier.verify_lifecycle_event": (3, 3),
    "AcdpVerifier.verify_lineage_head_receipt": (3, 6),
    "AcdpVerifier.verify_log_checkpoint": (2, 5),
    "AcdpVerifier.verify_log_consistency": (3, 3),
    "AcdpVerifier.verify_log_inclusion": (3, 3),
    "AcdpVerifier.verify_publish_request_offline": (1, 1),
    # The canary. 0.8.3 takes five positionals; 0.14.1 inserts `body_json` as
    # argument #2 (RFC-ACDP-0010 §8 step 3 cross-checks the served body), and
    # every positional call site in this repo breaks.
    "AcdpVerifier.verify_receipt": (5, 5),
    "AcdpVerifier.verify_signature": (3, 3),
    "AcdpVerifier.verify_signature_p256": (3, 3),
    "AcdpVerifier.verify_witness_cosignature": (3, 5),
}

#: Non-callable SDK attributes the repo reads. pyo3 getters carry no signature,
#: so these are existence-checked only.
EXPECTED_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "AcdpProducer.agent_did",
        "AcdpProducer.key_id",
        "AcdpProducer.public_key_b64",
        "AcdpP256Producer.agent_did",
        "AcdpP256Producer.key_id",
        "AcdpP256Producer.public_key_jwk",
        "AcdpP256Producer.public_key_sec1_b64",
    }
)


def _resolve(dotted: str) -> object:
    """Resolve ``"Class.member"`` on the installed `acdp` module."""
    class_name, member = dotted.split(".", 1)
    owner = getattr(acdp, class_name, None)
    assert owner is not None, f"acdp has no class {class_name!r} (surface drift)"
    assert hasattr(owner, member), f"acdp.{dotted} is gone (surface drift)"
    return getattr(owner, member)


def arity(dotted: str) -> tuple[int, int]:
    """``(required, total)`` parameter counts for ``acdp.<Class>.<method>``.

    Fails loudly — never skips — when the arity cannot be determined. A guard
    that silently disables itself when pyo3 stops emitting ``__text_signature__``
    is worse than no guard, and is the exact failure shape this file exists to
    prevent.
    """
    obj = _resolve(dotted)
    try:
        sig = inspect.signature(obj)
    except (TypeError, ValueError) as exc:
        raise AssertionError(
            f"cannot determine arity for acdp.{dotted}: {exc}. The surface guard "
            "must never skip — if pyo3/maturin stopped emitting __text_signature__, "
            "fix the guard deliberately rather than letting it lapse."
        ) from exc
    params = list(sig.parameters.values())
    positional = (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    )
    required = sum(
        1 for p in params if p.default is inspect.Parameter.empty and p.kind in positional
    )
    return required, len(params)


def _sdk_class_names() -> list[str]:
    """The `acdp` classes that carry callable surface (exceptions excluded)."""
    return sorted(
        name
        for name in dir(acdp)
        if not name.startswith("_")
        and inspect.isclass(getattr(acdp, name))
        and not issubclass(getattr(acdp, name), BaseException)
    )


def test_expected_surface_is_non_empty():
    assert EXPECTED_SURFACE, "the surface guard pins nothing — it is not guarding"
    assert "AcdpVerifier.verify_receipt" in EXPECTED_SURFACE


def test_every_called_symbol_exists():
    """Every pinned symbol still resolves on the installed wheel."""
    for dotted in sorted(EXPECTED_SURFACE) + sorted(EXPECTED_ATTRIBUTES):
        _resolve(dotted)


@pytest.mark.parametrize("dotted", sorted(EXPECTED_SURFACE))
def test_arity_matches_expected(dotted: str):
    expected = EXPECTED_SURFACE[dotted]
    actual = arity(dotted)
    assert actual == expected, (
        f"acdp.{dotted} arity drifted: expected (required, total)={expected}, "
        f"got {actual}. Fix the call sites, then update EXPECTED_SURFACE — "
        f"never the other way round."
    )


def test_unresolvable_arity_is_a_failure_not_a_skip(monkeypatch):
    """A symbol `inspect.signature` cannot read must FAIL, not silently pass.

    A pyo3 getset descriptor is exactly what a lost ``__text_signature__`` looks
    like from Python: the attribute is still there, but carries no signature.
    """
    opaque = acdp.AcdpProducer.__dict__["agent_did"]
    monkeypatch.setattr(acdp.AcdpVerifier, "verify_receipt", opaque, raising=False)

    with pytest.raises(AssertionError, match="cannot determine arity"):
        arity("AcdpVerifier.verify_receipt")


def test_missing_symbol_is_a_failure():
    """A removed symbol fails resolution rather than being quietly skipped."""
    with pytest.raises(AssertionError, match="surface drift"):
        _resolve("AcdpVerifier.method_that_does_not_exist")


def test_every_sdk_call_in_the_repo_is_registered():
    """Sweep the source for `Acdp<Class>.<member>` and assert each is pinned.

    Without this the guard's coverage is trusted rather than enforced: a new SDK
    call added without a matching entry would sit outside the pin entirely.
    """
    classes = _sdk_class_names()
    assert classes, "no acdp classes discovered — the sweep would pass vacuously"
    # Members starting with "_" are Python plumbing (`__dict__`, `__name__`),
    # not SDK surface.
    pattern = re.compile(r"\b(" + "|".join(classes) + r")\.([A-Za-z][A-Za-z0-9_]*)")

    registered = set(EXPECTED_SURFACE) | EXPECTED_ATTRIBUTES
    unregistered: dict[str, set[str]] = {}
    swept = 0
    for root in SOURCE_ROOTS:
        for path in sorted((REPO_ROOT / root).rglob("*.py")):
            if path.name in SWEEP_EXCLUDE:
                continue
            swept += 1
            for match in pattern.finditer(path.read_text(encoding="utf-8")):
                dotted = f"{match.group(1)}.{match.group(2)}"
                if dotted not in registered:
                    unregistered.setdefault(dotted, set()).add(str(path.relative_to(REPO_ROOT)))

    assert swept > 50, f"the sweep only read {swept} files — it is not covering the repo"

    assert not unregistered, (
        "SDK calls used in the repo but missing from EXPECTED_SURFACE / "
        "EXPECTED_ATTRIBUTES: "
        + ", ".join(f"{k} ({', '.join(sorted(v))})" for k, v in sorted(unregistered.items()))
    )
