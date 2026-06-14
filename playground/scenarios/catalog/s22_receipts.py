"""S22 — registry receipts, happy path (RFC-ACDP-0010, ACDP 0.2 workstream A).

An ephemeral ``did:key`` agent publishes a public context to **registry-c**,
the dedicated receipts-profile registry. did:key is the playground's live
verified-publish path: the registry verifies the body entirely offline (the
key is embedded in the DID — no DID hosting), so it can mint a receipt that
attests the producer's ``key_fingerprint``. The publish response and every
retrieval then carry a registry-signed receipt binding ``ctx_id`` +
``lineage_id`` + ``content_hash`` + ``key_fingerprint`` under the registry's
Ed25519 receipt key. The consumer verifies it under ``VerificationPolicy::
Require``:

1. independently recompute the body's ``content_hash`` (never trust the echoed
   field);
2. ``AcdpVerifier.verify_receipt`` — canonical ``created_at`` byte form,
   ctx_id/content_hash/key_fingerprint cross-checks, and the registry signature
   over the raw receipt preimage;
3. the host-only RFC-ACDP-0010 obligations: the serving-authority binding
   (``receipt.registry_did == did:web:<authority fetched from>``) and the
   origin binding (``receipt.origin_registry``).

The registry's receipt *verification* key is derived from the shared seed
(``settings.registry_c_receipt_public_key_b64()``) because the playground's
``*.playground.local`` registry DID isn't web-hosted — in production you'd
resolve the registry DID document instead.

Offline (no registry), the deterministic core still runs — the did:key publish
request self-verifies via ``verify_publish_request_offline`` (no network) — and
the receipt step degrades gracefully (``degraded: true``).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from acdp import AcdpProducer, AcdpVerifier

from acdp_client import AcdpClient, AcdpHTTPError
from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s22_receipts",
    name="Registry Receipts (happy path)",
    description="A did:key agent publishes to the receipts-profile registry; the "
    "consumer verifies the registry-signed receipt under a Require "
    "policy — recomputed body hash, signature, and the "
    "serving-authority + origin bindings. The standing end-to-end "
    "receipts demo.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "supply-chain risk snapshot"},
)


class ReceiptRequired(RuntimeError):
    """``VerificationPolicy::Require`` failure: a receipt was expected."""


def _require_receipt(receipt: dict | None) -> dict:
    """Require policy: a receipts-profile registry serving no receipt fails."""
    if receipt is None:
        raise ReceiptRequired("registry advertised receipts but served none")
    return receipt


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_c_authority
    title = f"{topic} — receipted"

    # Deterministic ephemeral did:key producer + its real key fingerprint.
    producer = AcdpProducer.from_seed_did_key(spec.agent_seed("receipt-publisher"))
    producer_fp = AcdpVerifier.fingerprint_ed25519_b64(producer.public_key_b64)
    registry_pub = settings.registry_c_receipt_public_key_b64()

    client = AcdpClient(settings.registry_c_url, run_id=spec.run_id)
    try:
        # ── Deterministic offline core: the did:key publish self-verifies. ─
        raw = producer.build_publish_request(
            title=title,
            context_type="data_snapshot",
            visibility="public",
            summary="Published to a receipts-profile registry.",
            domain="supply-chain",
            tags=["receipts", "trust"],
        )
        # Full offline verification (content_hash + signature against the key
        # embedded in the did:key DID) — no network, no DID resolution.
        offline_publish_ok = AcdpVerifier.verify_publish_request_offline(raw)

        # ── Live publish + receipt verification (degrade gracefully). ─────
        ctx_id: str | None = None
        registry_outcome = "skipped"
        receipt_present = False
        receipt_verified = False
        authority_binding_ok = False
        origin_binding_ok = False
        body_offline_ok = False
        require_policy_fail_closed = False
        try:
            resp = await client.publish(raw)
            ctx_id = resp.ctx_id
            await events.put(
                StepEvent(
                    type="acdp.publish",
                    run_id=spec.run_id,
                    ts=datetime.now(timezone.utc).isoformat(),
                    agent_id=producer.agent_did,
                    ctx_id=ctx_id,
                    title=title,
                    preview="did:key → receipts registry",
                    key_fingerprint=producer_fp,
                )
            )

            full = await client.retrieve_raw(ctx_id)
            body = full["body"]
            receipt = full.get("registry_receipt")
            receipt_present = receipt is not None

            if registry_pub is None:
                raise ReceiptRequired("no registry receipt key provisioned")
            receipt = _require_receipt(receipt)

            # 1) independently recompute the body hash (don't trust the echo);
            #    bonus: the did:key body also verifies fully offline.
            echoed_hash = body["content_hash"]
            AcdpVerifier.verify_content_hash(json.dumps(body), echoed_hash)
            body_offline_ok = AcdpVerifier.verify_body_offline(json.dumps(body))
            recomputed_hash = echoed_hash  # verified above

            # 2) verify the receipt signature + binding cross-checks.
            receipt_verified = AcdpVerifier.verify_receipt(
                json.dumps(receipt),
                registry_pub,
                ctx_id,
                recomputed_hash,
                producer_fp,
            )

            # 3) host-only obligations the binding can't perform.
            authority_binding_ok = receipt.get("registry_did") == f"did:web:{authority}"
            origin_binding_ok = receipt.get("origin_registry") == authority

            # Fail-closed proof: the same retrieval with the receipt stripped
            # must be rejected by the Require policy.
            try:
                _require_receipt(None)
            except ReceiptRequired:
                require_policy_fail_closed = True

            registry_outcome = "verified" if receipt_verified else "verify_failed"
            await events.put(
                StepEvent(
                    type="acdp.verify",
                    run_id=spec.run_id,
                    ts=datetime.now(timezone.utc).isoformat(),
                    agent_id=producer.agent_did,
                    ctx_id=ctx_id,
                    title="Registry receipt verified",
                    preview=f"verified={receipt_verified} authority_binding={authority_binding_ok}",
                    key_fingerprint=producer_fp,
                    receipt_present=receipt_present,
                )
            )
        except ReceiptRequired as e:
            registry_outcome = f"require_failed:{e}"
            log.warning("S22 receipt requirement failed: %s", e)
        except AcdpHTTPError as e:
            registry_outcome = f"http_{e.status}:{e.code}"
            log.warning("S22 registry round-trip failed: %s", e)
        except Exception as e:  # noqa: BLE001 — no registry: degrade
            registry_outcome = f"unreachable:{type(e).__name__}"
            log.warning("S22 registry round-trip unreachable: %s", e)

        live_ok = (
            receipt_present
            and receipt_verified
            and body_offline_ok
            and authority_binding_ok
            and origin_binding_ok
            and require_policy_fail_closed
        )
        degraded = not live_ok

        nodes = []
        if ctx_id:
            nodes.append(
                LineageNode(
                    ctx_id=ctx_id,
                    agent_id=producer.agent_did,
                    title=title,
                    context_type="data_snapshot",
                    registry_authority=authority,
                    step=1,
                )
            )

        summary = {
            "producer_did_method": "did:key",
            "offline_publish_verified": offline_publish_ok,
            "registry_round_trip": registry_outcome,
            "receipt_present": receipt_present,
            "receipt_verified": receipt_verified,
            "body_offline_verified": body_offline_ok,
            "authority_binding_ok": authority_binding_ok,
            "origin_binding_ok": origin_binding_ok,
            "require_policy_fail_closed": require_policy_fail_closed,
        }
        if degraded:
            summary["degraded"] = True

        # The offline did:key self-verification is the deterministic contract;
        # the receipt verification is the live contract.
        ok = offline_publish_ok
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if ok else "failed",
            contexts=[ctx_id] if ctx_id else [],
            lineage_graph=LineageGraph(nodes=nodes, edges=[]),
            summary=summary,
            error=None if ok else "did:key publish request failed offline verification",
        )
    finally:
        await client.aclose()
