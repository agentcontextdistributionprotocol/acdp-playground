"""S24 — historical key / rotated-key verification (RFC-ACDP-0010 + 0008 §9.3).

The trust gap this closes: a producer rotates its signing key, and a consumer
later needs to verify a context signed with the *pre-rotation* key. The body
signature still verifies as long as the old key is retained in the DID
document's ``verificationMethod`` — but "the key verifies" isn't "the key was
*authorized to publish this*". The registry receipt's ``key_fingerprint`` is
what closes that: it records the producer key the registry resolved **at
publish time**, so the consumer can establish *HistoricallyAuthorized* even
after rotation.

The *HistoricallyAuthorized* decision delegates the RFC-ACDP-0010 §9 key
lifecycle to the SDK: the consumer parses the producer's DID document and
resolves the key the receipt names through
:meth:`AcdpDidDocument.receipt_key_for_algorithm` (the 0.5.0 primitive), which
resolves a retired-but-retained key with ``historical=true`` and raises
``key_not_found`` once the key is removed — the playground no longer hand-rolls
that lifecycle. The fingerprint→key_id lookup and the body-signature check stay
in the host language (no SDK primitive maps a producer fingerprint to a key).

Deterministic core (offline):

* Rotation produces two distinct keys (``key_v1`` at ``#key-1`` → ``key_v2`` at
  ``#key-2``) for one DID.
* The pre-rotation body signature verifies under the retained ``key_v1`` and
  NOT under ``key_v2`` — rotation didn't invalidate past signatures.
* *HistoricallyAuthorized* decision: a receipt whose ``key_fingerprint`` matches
  a key still resolvable in the DID document (now retired → ``historical=true``)
  ⇒ authorized; a **stripped** receipt ⇒ fail closed (you can no longer prove
  the signing key was the authorized one).
* Variant — old key fully **removed** from the DID document: resolution raises
  ``key_not_found`` so historical verification fails *even with* a matching-intent
  receipt. This documents the producer's obligation to retain rotated keys.

The live half publishes with ``key_v1`` and, if the registry issues a receipt,
asserts ``receipt.key_fingerprint == fingerprint(key_v1)`` — the publish-time
key is recorded. It degrades gracefully without a registry (and the playground
DIDs aren't web-hosted, so full rotation lives in the offline core, mirroring
S12).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone

from acdp import AcdpDidDocument, AcdpProducer, AcdpVerifier, DidResolutionError

from acdp_client import AcdpHTTPError
from acdp_client.models import StepEvent
from acdp_client.signing import verify_signature

from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, did_for
from playground.scenarios._receipts import did_document, ed25519_jwk_vm
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s24_historical_key",
    name="Historical Key Verification",
    description="A producer rotates its key; a consumer verifies a pre-rotation "
    "context as HistoricallyAuthorized via the receipt fingerprint "
    "(old key retained), and fails closed when the receipt is "
    "stripped or the old key is removed.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "long-lived provenance record"},
)


class HistoricalAuthFailed(RuntimeError):
    """Fail-closed: historical authorization could not be established."""


def _fp(pub_b64: str) -> str:
    return AcdpVerifier.fingerprint_ed25519_b64(pub_b64)


def _historically_authorized(
    receipt: dict | None,
    *,
    sig_value: str,
    content_hash: str,
    doc: AcdpDidDocument,
    candidate_key_ids: list[str],
) -> tuple[bool, bool]:
    """Host-language *HistoricallyAuthorized* decision, §9 resolution delegated.

    The receipt's ``key_fingerprint`` names the producer key the registry
    resolved at publish time. We locate it among ``candidate_key_ids`` by
    resolving each through :meth:`AcdpDidDocument.receipt_key_for_algorithm` —
    the SDK applies the RFC-ACDP-0010 §9 lifecycle (a retired-but-retained key
    resolves with ``historical=true``; a removed key raises ``key_not_found``,
    which we skip) and the algorithm-downgrade defense. The matched key must
    then verify the body signature. A missing receipt, or a fingerprint that
    resolves to no retained key, fails closed. Returns ``(authorized,
    historical)``.
    """
    if receipt is None:
        raise HistoricalAuthFailed(
            "no receipt — cannot prove the signing key was authorized at publish time"
        )
    fp = receipt.get("key_fingerprint")
    for key_id in candidate_key_ids:
        try:
            resolved = doc.receipt_key_for_algorithm(key_id, "ed25519")
        except DidResolutionError:
            continue  # key removed / not resolvable — not a candidate
        if _fp(resolved["public_key_b64"]) != fp:
            continue
        # The body signature must verify under that historical key.
        authorized = verify_signature(
            "ed25519", resolved["public_key_b64"], sig_value, content_hash
        )
        return authorized, resolved["historical"] == "true"
    raise HistoricalAuthFailed(
        f"receipt key_fingerprint {fp} resolves to no retained key "
        "(rotated key was removed from the DID document)"
    )


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority

    try:
        did = did_for(authority, "rotating-historical")
        # Distinct verification-method fragments for one DID: a rotation mints a
        # NEW key id, so the retired key can be retained alongside the current.
        kid_v1, kid_v2 = f"{did}#key-1", f"{did}#key-2"
        seed = spec.agent_seed("rotating-historical")
        # Two keys for ONE DID: v1 (pre-rotation), v2 (post-rotation).
        key_v1 = AcdpProducer.from_seed(hashlib.sha256(seed + b":v1").digest(), did, kid_v1)
        key_v2 = AcdpProducer.from_seed(hashlib.sha256(seed + b":v2").digest(), did, kid_v2)
        fp_v1, fp_v2 = _fp(key_v1.public_key_b64), _fp(key_v2.public_key_b64)
        rotation_distinct = key_v1.public_key_b64 != key_v2.public_key_b64 and fp_v1 != fp_v2
        vm_v1 = ed25519_jwk_vm(kid_v1, did, key_v1.public_key_b64)
        vm_v2 = ed25519_jwk_vm(kid_v2, did, key_v2.public_key_b64)
        candidate_key_ids = [kid_v1, kid_v2]

        # Pre-rotation context, signed by key_v1.
        title = f"{topic} — pre-rotation"
        raw_v1 = key_v1.build_publish_request(
            title=title,
            context_type="analysis",
            visibility="public",
            summary="Signed with the pre-rotation key.",
            domain="provenance",
            tags=["rotation", "historical"],
        )
        req_v1 = json.loads(raw_v1)
        ch_v1, sig_v1 = req_v1["content_hash"], req_v1["signature"]["value"]

        # Pre-rotation signature verifies under the retained old key, not the new.
        pre_verifies_old = verify_signature("ed25519", key_v1.public_key_b64, sig_v1, ch_v1)
        new_key_rejects = False
        try:
            verify_signature("ed25519", key_v2.public_key_b64, sig_v1, ch_v1)
        except Exception:  # noqa: BLE001
            new_key_rejects = True

        # A receipt that binds the publish-time key (fp_v1).
        receipt_v1 = {"key_fingerprint": fp_v1}

        # Case A — old key RETAINED (verificationMethod, retired from
        # assertionMethod) alongside the current key: HistoricallyAuthorized,
        # and the SDK reports it as historical.
        doc_retained = AcdpDidDocument.parse(
            did_document(did, current=[vm_v2], retired=[vm_v1]), did
        )
        historically_authorized, historical_flag = _historically_authorized(
            receipt_v1,
            sig_value=sig_v1,
            content_hash=ch_v1,
            doc=doc_retained,
            candidate_key_ids=candidate_key_ids,
        )

        # Case B — receipt STRIPPED: must fail closed.
        stripped_fail_closed = False
        try:
            _historically_authorized(
                None,
                sig_value=sig_v1,
                content_hash=ch_v1,
                doc=doc_retained,
                candidate_key_ids=candidate_key_ids,
            )
        except HistoricalAuthFailed:
            stripped_fail_closed = True

        # Case C — old key REMOVED from the DID document: resolution raises
        # key_not_found, so it fails even WITH a matching-intent receipt
        # (documents the producer's retain obligation).
        doc_removed = AcdpDidDocument.parse(did_document(did, current=[vm_v2]), did)
        removed_key_fail_closed = False
        try:
            _historically_authorized(
                receipt_v1,
                sig_value=sig_v1,
                content_hash=ch_v1,
                doc=doc_removed,
                candidate_key_ids=candidate_key_ids,
            )
        except HistoricalAuthFailed:
            removed_key_fail_closed = True

        offline_core_ok = (
            rotation_distinct
            and pre_verifies_old
            and new_key_rejects
            and historically_authorized
            and historical_flag
            and stripped_fail_closed
            and removed_key_fail_closed
        )

        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=did,
                title="Historical key verification",
                preview=f"historically_authorized={historically_authorized} "
                f"(historical={historical_flag}); "
                f"stripped_fail_closed={stripped_fail_closed}; "
                f"removed_key_fail_closed={removed_key_fail_closed}",
            )
        )

        # ── Live: publish with key_v1; assert the receipt records fp_v1. ──
        client = bundle.anonymous_client("a")
        registry_pub = settings.registry_c_receipt_public_key_b64()
        ctx_id: str | None = None
        registry_outcome = "skipped"
        receipt_records_publish_key = False
        try:
            resp = await client.publish(raw_v1)
            ctx_id = resp.ctx_id
            await events.put(
                StepEvent(
                    type="acdp.publish",
                    run_id=spec.run_id,
                    ts=datetime.now(timezone.utc).isoformat(),
                    agent_id=did,
                    ctx_id=ctx_id,
                    title=title,
                    preview="pre-rotation key",
                    key_fingerprint=fp_v1,
                )
            )
            full = await client.retrieve_raw(ctx_id)
            receipt = full.get("registry_receipt")
            if receipt is not None and registry_pub is not None:
                body = full["body"]
                AcdpVerifier.verify_content_hash(json.dumps(body), body["content_hash"])
                AcdpVerifier.verify_receipt(
                    json.dumps(receipt), registry_pub, ctx_id, body["content_hash"], fp_v1
                )
                receipt_records_publish_key = receipt.get("key_fingerprint") == fp_v1
                registry_outcome = "verified" if receipt_records_publish_key else "fp_mismatch"
            else:
                registry_outcome = "no_receipt"
            await events.put(
                StepEvent(
                    type="acdp.verify",
                    run_id=spec.run_id,
                    ts=datetime.now(timezone.utc).isoformat(),
                    agent_id=did,
                    ctx_id=ctx_id,
                    title="Receipt records the publish-time key",
                    preview=f"records_publish_key={receipt_records_publish_key}",
                    key_fingerprint=fp_v1,
                    receipt_present=receipt is not None,
                )
            )
        except AcdpHTTPError as e:
            registry_outcome = f"http_{e.status}:{e.code}"
            log.warning("S24 registry round-trip failed: %s", e)
        except Exception as e:  # noqa: BLE001 — no registry: degrade
            registry_outcome = f"unreachable:{type(e).__name__}"
            log.warning("S24 registry round-trip unreachable: %s", e)

        degraded = not receipt_records_publish_key

        nodes = []
        if ctx_id:
            nodes.append(
                LineageNode(
                    ctx_id=ctx_id,
                    agent_id=did,
                    title=title,
                    context_type="analysis",
                    registry_authority=authority,
                    step=1,
                )
            )

        summary = {
            "rotation_distinct": rotation_distinct,
            "pre_rotation_verifies_under_old_key": pre_verifies_old,
            "new_key_rejects_old_signature": new_key_rejects,
            "historically_authorized": historically_authorized,
            "resolved_as_historical": historical_flag,
            "stripped_receipt_fail_closed": stripped_fail_closed,
            "removed_key_fail_closed": removed_key_fail_closed,
            "offline_core_ok": offline_core_ok,
            "registry_round_trip": registry_outcome,
            "receipt_records_publish_key": receipt_records_publish_key,
        }
        if degraded:
            summary["degraded"] = True

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if offline_core_ok else "failed",
            contexts=[ctx_id] if ctx_id else [],
            lineage_graph=LineageGraph(nodes=nodes, edges=[]),
            summary=summary,
            error=None if offline_core_ok else "historical key verification core failed",
        )
    finally:
        await bundle.aclose()
