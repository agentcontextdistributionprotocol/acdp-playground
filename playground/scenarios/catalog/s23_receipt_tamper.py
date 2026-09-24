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
``content_hash`` (body re-binding), an invalid signature, and the two §8 step 3
*served-body* bindings — ``lineage_id`` and ``origin_registry``. Those last two
are only expressible because ``verify_receipt`` takes the served body: the
receipt is otherwise self-consistent, so nothing else in the §8 sequence sees
the substitution.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from datetime import UTC, datetime

from acdp import AcdpVerifier

from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id
from acdp_client.models import StepEvent
from playground.config import get_settings
from playground.scenarios._factory import producer_for
from playground.scenarios._receipts import synthesize_retrieval_body
from playground.scenarios._sdk_guard import expect_rejection
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
    body: dict,
    registry_pub: str,
    expected_ctx: str,
    recomputed_hash: str,
    producer_fp: str,
) -> tuple[bool, str]:
    """Run verify_receipt and assert it FAILS closed. Returns (rejected, why).

    ``body`` is the object the registry served alongside the receipt —
    RFC-ACDP-0010 §8 step 3 binds the receipt's ``lineage_id`` /
    ``origin_registry`` / ``created_at`` to it.

    Only failures the SDK can actually *express* count as a rejection — a
    ``TypeError`` from calling ``verify_receipt`` wrongly propagates instead of
    being scored 8/8 fail-closed (see :mod:`playground.scenarios._sdk_guard`).
    """
    rejected, why = expect_rejection(
        lambda: AcdpVerifier.verify_receipt(
            json.dumps(receipt),
            json.dumps(body),
            registry_pub,
            expected_ctx,
            recomputed_hash,
            producer_fp,
        )
    )
    if not rejected:
        return False, "verify_receipt accepted a tampered receipt"
    return True, why


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

    ctx_id = synthetic_ctx_id(authority, "s23-tamper-victim")
    lineage_id = synthetic_lineage_id("s23-tamper-victim")
    created_at = "2026-06-12T00:00:00.000Z"

    # The body the honest registry served for that context: a real signed
    # publish request plus the four fields a registry assigns. The receipt
    # attests *this* body — RFC-ACDP-0010 §8 step 3 cross-checks the receipt's
    # lineage_id / origin_registry / created_at against it, which is what makes
    # cases (g) and (h) below expressible at all.
    body = synthesize_retrieval_body(
        producer.build_publish_request(
            title="Receipted context under attack",
            context_type="analysis",
            visibility="public",
            summary="The body a misbehaving registry serves tampered receipts for.",
            domain="provenance",
            tags=["receipts", "tamper"],
        ),
        ctx_id=ctx_id,
        lineage_id=lineage_id,
        origin_registry=authority,
        created_at=created_at,
    )
    body_hash = body["content_hash"]

    # A structurally-valid receipt skeleton (all 8 RFC-ACDP-0010 fields), whose
    # bindings match that body exactly. Its signature is intentionally bogus —
    # every adversarial variant is caught on a *binding* cross-check before the
    # signature is even reached, except the "valid bindings / bad signature"
    # case which exercises the signature gate.
    base = {
        "registry_did": f"did:web:{authority}",
        "ctx_id": ctx_id,
        "lineage_id": lineage_id,
        "origin_registry": authority,
        "created_at": created_at,
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
        body=body,
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
        body=body,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash=body_hash,
        producer_fp=producer_fp,
    )
    checks["mismatched_fingerprint"] = {"rejected": rejected, "why": why[:120]}

    # (d) Re-bound ctx_id — receipt points at a different context.
    bad = copy.deepcopy(base)
    bad["ctx_id"] = synthetic_ctx_id(authority, "s23-tamper-other-context")
    rejected, why = _expect_rejected(
        "ctx_id",
        bad,
        body=body,
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
        body=body,
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
        body=body,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash=body_hash,
        producer_fp=producer_fp,
    )
    checks["forged_signature"] = {"rejected": rejected, "why": why[:120]}

    # (g) Re-bound lineage_id — the receipt claims a lineage the served body
    #     does not belong to (§8 step 3). Everything cross_check covers still
    #     matches, so only the body binding can catch this.
    bad = copy.deepcopy(base)
    bad["lineage_id"] = synthetic_lineage_id("s23-tamper-other-lineage")
    rejected, why = _expect_rejected(
        "lineage_id",
        bad,
        body=body,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash=body_hash,
        producer_fp=producer_fp,
    )
    # Be specific. A bare "it raised" would also be satisfied by a malformed
    # identifier, a bad signature, or any earlier §8 gate; only
    # cross_check_body's message says "body lineage_id".
    checks["rebound_lineage_id"] = {
        "rejected": rejected and "body lineage_id" in why,
        "why": why[:200],
    }

    # (h) Re-bound origin_registry — the receipt attributes the served body to
    #     a different registry of origin (§8 step 3). ``registry_did`` moves
    #     with it: cross_check enforces registry_did == did:web:<origin_registry>
    #     *within* the receipt and would otherwise reject on that internal
    #     inconsistency long before the body is consulted. So the adversary is
    #     a second registry issuing an internally-perfect receipt for someone
    #     else's body — which is exactly the case step 3 exists for.
    other_authority = settings.registry_b_authority
    bad = copy.deepcopy(base)
    bad["origin_registry"] = other_authority
    bad["registry_did"] = f"did:web:{other_authority}"
    bad["signature"]["key_id"] = f"did:web:{other_authority}#receipt-key-1"
    rejected, why = _expect_rejected(
        "origin_registry",
        bad,
        body=body,
        registry_pub=registry_pub,
        expected_ctx=ctx_id,
        recomputed_hash=body_hash,
        producer_fp=producer_fp,
    )
    checks["rebound_origin_registry"] = {
        "rejected": rejected and "body origin_registry" in why,
        "why": why[:200],
    }

    all_failed_closed = all(c["rejected"] for c in checks.values())

    await events.put(
        StepEvent(
            type="acdp.verify",
            run_id=spec.run_id,
            ts=datetime.now(UTC).isoformat(),
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
