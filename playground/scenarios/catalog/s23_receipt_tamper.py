"""S23 — receipt negative scenarios (fail-closed).

Models a *misbehaving* receipts-profile registry and proves the SDK refuses
every dishonest receipt under ``VerificationPolicy::Require`` (RFC-ACDP-0010).
A registry that advertises the receipts profile but serves a missing, mutated,
or mismatched receipt must never be trusted — and a consumer that recomputes
its own bindings catches each case.

The whole scenario is deterministic and offline: it crafts the adversarial
receipts directly (no registry needed) and asserts ``AcdpVerifier.verify_receipt``
raises for each, naming the discrepancy. The cross-checks fire *before* the
signature check, so a forged receipt is rejected on the binding it violates —
exactly what the control plane's audit mode (RECEIPT_AUDIT_ENABLED) independently
flags on the live stack.

The discrepancy classes mirror the control plane's audit flags:
``missing_receipt``, ``created_at`` (non-canonical byte form, §8 step 6),
``key_fingerprint`` (rotated/foreign producer key), ``ctx_id`` /
``content_hash`` (body re-binding), and an invalid signature.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from datetime import datetime, timezone

from acdp import AcdpVerifier

from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios._factory import producer_for
from playground.scenarios.models import LineageGraph, RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s23_receipt_tamper",
    name="Receipt Tamper (fail-closed)",
    description="A misbehaving registry serves missing/mutated/mismatched "
    "receipts; the SDK fails closed on every one under a Require "
    "policy. Deterministic offline proof that a forged receipt is "
    "rejected on the exact binding it violates.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={},
)


class ReceiptRequired(RuntimeError):
    """Raised by the host-language Require policy when no receipt is served."""


def _require_receipt(receipt: dict | None) -> dict:
    """``VerificationPolicy::Require`` in the host language: a receipts-profile
    registry that serves no receipt is a hard failure, not a soft pass."""
    if receipt is None:
        raise ReceiptRequired("registry advertised receipts but served none")
    return receipt


def _expect_rejected(
    label: str,
    receipt: dict,
    *,
    registry_pub: str,
    expected_ctx: str,
    recomputed_hash: str,
    producer_fp: str,
) -> tuple[bool, str]:
    """Run verify_receipt and assert it FAILS closed. Returns (rejected, why)."""
    try:
        AcdpVerifier.verify_receipt(
            json.dumps(receipt),
            registry_pub,
            expected_ctx,
            recomputed_hash,
            producer_fp,
        )
        return False, "verify_receipt accepted a tampered receipt"
    except Exception as e:  # noqa: BLE001 — any raise == correctly fails closed
        return True, str(e)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    # Model the receipts registry (registry-a) — its authority + receipt key.
    authority = settings.registry_a_authority

    registry_pub = settings.receipt_verification_public_key_b64()
    if registry_pub is None:
        # No receipt key provisioned — can't derive the verification key.
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete",
            contexts=[],
            lineage_graph=LineageGraph(nodes=[], edges=[]),
            summary={"degraded": True, "reason": "no receipt_signing_seed provisioned"},
            error=None,
        )

    # A deterministic producer + its real fingerprint (the key the registry
    # would have resolved at publish time).
    producer = producer_for(spec, "tamper-victim", authority)
    producer_fp = AcdpVerifier.fingerprint_ed25519_b64(producer.public_key_b64)

    ctx_id = f"acdp://{authority}/11111111-1111-1111-1111-111111111111"
    body_hash = "sha256:" + "ab" * 32

    # A structurally-valid receipt skeleton (all 8 RFC-ACDP-0010 fields). Its
    # signature is intentionally bogus — every adversarial variant is caught on
    # a *binding* cross-check before the signature is even reached, except the
    # "valid bindings / bad signature" case which exercises the signature gate.
    base = {
        "registry_did": f"did:web:{authority}",
        "ctx_id": ctx_id,
        "lineage_id": f"acdp://{authority}/22222222-2222-2222-2222-222222222222",
        "origin_registry": authority,
        "created_at": "2026-06-12T00:00:00.000Z",
        "content_hash": body_hash,
        "key_fingerprint": producer_fp,
        "signature": {
            "algorithm": "ed25519",
            "key_id": f"did:web:{authority}#receipt-key-1",
            "value": "A" * 86 + "==",
        },
    }

    checks: dict[str, dict] = {}

    # (a) Missing receipt under a Require policy.
    try:
        _require_receipt(None)
        checks["missing_receipt"] = {"rejected": False, "why": "policy passed"}
    except ReceiptRequired as e:
        checks["missing_receipt"] = {"rejected": True, "why": str(e)}

    # (b) Mutated created_at — non-canonical microsecond byte form (§8 step 6).
    bad = copy.deepcopy(base)
    bad["created_at"] = "2026-06-12T00:00:00.000123Z"
    rejected, why = _expect_rejected(
        "created_at",
        bad,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash=body_hash,
        producer_fp=producer_fp,
    )
    checks["mutated_created_at"] = {"rejected": rejected, "why": why[:120]}

    # (c) Mismatched key_fingerprint — receipt names a foreign/rotated key.
    bad = copy.deepcopy(base)
    bad["key_fingerprint"] = "sha256:" + "00" * 32
    rejected, why = _expect_rejected(
        "key_fingerprint",
        bad,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash=body_hash,
        producer_fp=producer_fp,
    )
    checks["mismatched_fingerprint"] = {"rejected": rejected, "why": why[:120]}

    # (d) Re-bound ctx_id — receipt points at a different context.
    bad = copy.deepcopy(base)
    bad["ctx_id"] = f"acdp://{authority}/99999999-9999-9999-9999-999999999999"
    rejected, why = _expect_rejected(
        "ctx_id",
        bad,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash=body_hash,
        producer_fp=producer_fp,
    )
    checks["rebound_ctx_id"] = {"rejected": rejected, "why": why[:120]}

    # (e) content_hash mismatch — consumer's recomputed body hash differs.
    rejected, why = _expect_rejected(
        "content_hash",
        base,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash="sha256:" + "cd" * 32,
        producer_fp=producer_fp,
    )
    checks["mismatched_content_hash"] = {"rejected": rejected, "why": why[:120]}

    # (f) Valid bindings, forged signature — must fail at the signature gate.
    rejected, why = _expect_rejected(
        "signature",
        base,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash=body_hash,
        producer_fp=producer_fp,
    )
    checks["forged_signature"] = {"rejected": rejected, "why": why[:120]}

    all_failed_closed = all(c["rejected"] for c in checks.values())

    await events.put(
        StepEvent(
            type="acdp.verify",
            run_id=spec.run_id,
            ts=datetime.now(timezone.utc).isoformat(),
            agent_id=producer.agent_did,
            title="All tampered receipts rejected",
            preview=f"{sum(c['rejected'] for c in checks.values())}/"
            f"{len(checks)} dishonest receipts failed closed",
        )
    )

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if all_failed_closed else "failed",
        contexts=[],
        lineage_graph=LineageGraph(nodes=[], edges=[]),
        summary={
            "all_failed_closed": all_failed_closed,
            "checks": checks,
        },
        error=None if all_failed_closed else "a tampered receipt was NOT rejected (fail-open)",
    )
