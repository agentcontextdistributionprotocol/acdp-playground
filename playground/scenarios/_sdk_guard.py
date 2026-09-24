"""Narrow the "any raise == the SDK rejected it" pattern down to real rejections.

Several scenarios assert a *negative*: the SDK must refuse a tampered receipt, a
forged publish request, an illegal lineage guard. Written the obvious way —
``try: sdk_call() ... except Exception: rejected = True`` — that assertion cannot
tell "the SDK rejected the input" apart from "we called the SDK wrong". A
call-convention break (a renamed keyword, a new required positional argument)
raises :class:`TypeError`, and a broad handler scores it as the security control
working. The scenario stays green while the check it claims to make is no longer
running at all.

That is not hypothetical: ``AcdpVerifier.verify_receipt`` gained a required
argument between SDK releases, and the six-case S23 tamper matrix kept reporting
``6/6 rejected`` on the strength of six ``TypeError``\\ s.

The fix is to accept only the rejections the SDK can actually *express*:

* :class:`RuntimeError` — the pyo3 default for a failed verification
  (``signature invalid``, ``content_hash mismatch``, ``schema violation``), and
  the base of the playground's own :class:`acdp_client.AcdpHTTPError` family;
* :class:`ValueError` — malformed input the bindings reject before verifying;
* the four typed exceptions the bindings define (``InvalidLogProof``,
  ``ImmutableField``, ``InvalidLifecycleTransition``,
  ``InvalidWitnessCosignature``).

Everything else — :class:`TypeError` above all — propagates, so a call-convention
break surfaces as a loud run error instead of a silent false pass. The companion
pin on the SDK's own signatures lives in ``tests/test_sdk_surface.py``.

This module owns no protocol logic; it is pure host-language plumbing, so the
CLAUDE.md delegation boundary is untouched.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from acdp import (
    ImmutableField,
    InvalidLifecycleTransition,
    InvalidLogProof,
    InvalidWitnessCosignature,
)

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["SDK_REJECTIONS", "expect_rejection", "run_guarded"]

#: The complete set of failures the `acdp` bindings can raise *as a verdict*.
#: Deliberately does **not** include :class:`TypeError` (a call-convention bug on
#: our side) or :class:`acdp.DidResolutionError` / :class:`acdp.SsrfRejected`,
#: which callers that care about them catch by name.
SDK_REJECTIONS: tuple[type[BaseException], ...] = (
    RuntimeError,
    ValueError,
    ImmutableField,
    InvalidLifecycleTransition,
    InvalidLogProof,
    InvalidWitnessCosignature,
)


def run_guarded(
    fn: Callable[[], Any],
    *,
    allow: tuple[type[BaseException], ...] = SDK_REJECTIONS,
) -> tuple[Any, BaseException | None]:
    """Call ``fn()`` under the narrow allow-list.

    Returns ``(value, None)`` when ``fn`` returned, and ``(None, exc)`` when it
    raised something in ``allow``. Anything outside ``allow`` propagates — which
    is the whole point of this module.
    """
    try:
        return fn(), None
    except allow as exc:
        return None, exc


def expect_rejection(
    fn: Callable[[], Any],
    *,
    allow: tuple[type[BaseException], ...] = SDK_REJECTIONS,
) -> tuple[bool, str]:
    """Assert ``fn()`` is refused by the SDK; report ``(rejected, why)``.

    ``rejected`` is ``True`` only when ``fn`` raised one of ``allow``; ``why`` is
    that exception's message (empty string when ``fn`` returned normally). A
    :class:`TypeError` — the arity/keyword break this guard exists for — is *not*
    a rejection and propagates to the caller.
    """
    _, exc = run_guarded(fn, allow=allow)
    return (exc is not None), ("" if exc is None else str(exc))
