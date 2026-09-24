"""The regression test for the "any raise == the SDK rejected it" trap.

`playground.scenarios._sdk_guard` exists because a scenario asserting a negative
cannot tell "the SDK rejected the input" from "we called the SDK wrong" when it
catches bare :class:`Exception`. These tests pin both halves of that contract:
the rejections the SDK can express are absorbed, and a :class:`TypeError` — the
arity/keyword break — propagates.
"""

from __future__ import annotations

import pytest
from acdp import (
    ImmutableField,
    InvalidLifecycleTransition,
    InvalidLogProof,
    InvalidWitnessCosignature,
)

from playground.scenarios._sdk_guard import SDK_REJECTIONS, expect_rejection, run_guarded


def _raiser(exc: BaseException):
    def _fn():
        raise exc

    return _fn


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("signature invalid: signature verification failed"),
        ValueError("malformed receipt json"),
        InvalidLogProof("inclusion proof does not reconstruct the root"),
        ImmutableField("body content is immutable"),
        InvalidLifecycleTransition("already retracted"),
        InvalidWitnessCosignature("witness cosignature does not verify"),
    ],
)
def test_expect_rejection_allows_sdk_errors(exc: BaseException):
    """Every failure the `acdp` bindings can express counts as a rejection."""
    rejected, why = expect_rejection(_raiser(exc))
    assert rejected is True
    assert why == str(exc)


def test_expect_rejection_reports_a_non_rejection():
    rejected, why = expect_rejection(lambda: "verified")
    assert rejected is False
    assert why == ""


def test_expect_rejection_propagates_type_error():
    """The whole point: a call-convention break is never a 'fail-closed' pass.

    An SDK method that gains a required positional argument raises TypeError at
    the call site. Scoring that as a rejection is how a broken verification call
    kept reporting 6/6 tampered receipts rejected.
    """
    boom = TypeError("verify_receipt() missing 1 required positional argument: 'body_json'")
    with pytest.raises(TypeError, match="missing 1 required positional argument"):
        expect_rejection(_raiser(boom))


def test_type_error_is_not_in_the_allow_list():
    assert TypeError not in SDK_REJECTIONS
    assert not any(issubclass(TypeError, allowed) for allowed in SDK_REJECTIONS)


def test_run_guarded_returns_the_value_on_success():
    value, exc = run_guarded(lambda: {"verified": True})
    assert value == {"verified": True}
    assert exc is None


def test_run_guarded_returns_the_exception_on_rejection():
    boom = RuntimeError("content_hash mismatch")
    value, exc = run_guarded(_raiser(boom))
    assert value is None
    assert exc is boom


def test_run_guarded_propagates_type_error():
    with pytest.raises(TypeError):
        run_guarded(_raiser(TypeError("unexpected keyword argument 'expected_ctx_id'")))


def test_allow_override_narrows_further():
    """A caller may pin an even narrower set; anything outside it propagates."""
    rejected, _ = expect_rejection(_raiser(ValueError("bad")), allow=(ValueError,))
    assert rejected is True
    with pytest.raises(RuntimeError):
        expect_rejection(_raiser(RuntimeError("bad")), allow=(ValueError,))
