"""S24 — historical key / rotated-key verification (RFC-ACDP-0010 + 0008 §9.3).

The trust gap this closes: a producer rotates its signing key, and a consumer
later needs to verify a context signed with the *pre-rotation* key. The body
signature still verifies as long as the old key is retained in the DID
document's ``verificationMethod`` — but "the key verifies" isn't "the key was
*authorized to publish this*". The registry receipt's ``key_fingerprint`` is
what closes that: it records the producer key the registry resolved **at
publish time**, so the consumer can establish *HistoricallyAuthorized* even
after rotation.

Deterministic core (offline):

* Rotation produces two distinct keys (``key_v1`` → ``key_v2``) for one DID.
* The pre-rotation body signature verifies under the retained ``key_v1`` and
  NOT under ``key_v2`` — rotation didn't invalidate past signatures.
* *HistoricallyAuthorized* decision: a receipt whose ``key_fingerprint`` matches
  a retained key ⇒ authorized; a **stripped** receipt ⇒ fail closed (you can no
  longer prove the signing key was the authorized one).
* Variant — old key fully **removed** from the DID document: historical
  verification fails *even with* a receipt whose fingerprint matches nothing
  resolvable. This documents the producer's obligation to retain rotated keys.

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

from acdp import AcdpProducer, AcdpVerifier

from acdp_client import AcdpHTTPError
from acdp_client.models import StepEvent
from acdp_client.signing import verify_signature

from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, did_for, key_id_for
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
    retained_keys: dict[str, str],
) -> bool:
    """Host-language *HistoricallyAuthorized* decision.

    ``retained_keys`` maps fingerprint → public-key-b64 currently resolvable in
    the producer's DID document. The receipt's ``key_fingerprint`` names the
    key the registry resolved at publish time; we require that key to still be
    resolvable AND the body signature to verify under it. A missing receipt or
    an unresolvable historical key fails closed.
    """
    if receipt is None:
        raise HistoricalAuthFailed(
            "no receipt — cannot prove the signing key was authorized at publish time"
        )
    fp = receipt.get("key_fingerprint")
    pub = retained_keys.get(fp)
    if pub is None:
        raise HistoricalAuthFailed(
            f"receipt key_fingerprint {fp} resolves to no retained key "
            "(rotated key was removed from the DID document)"
        )
    # The body signature must verify under that historical key.
    return verify_signature("ed25519", pub, sig_value, content_hash)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority

    try:
        did = did_for(authority, "rotating-historical")
        key_id = key_id_for(authority, "rotating-historical")
        seed = spec.agent_seed("rotating-historical")
        # Two keys for ONE DID: v1 (pre-rotation), v2 (post-rotation).
        key_v1 = AcdpProducer.from_seed(hashlib.sha256(seed + b":v1").digest(), did, key_id)
        key_v2 = AcdpProducer.from_seed(hashlib.sha256(seed + b":v2").digest(), did, key_id)
        fp_v1, fp_v2 = _fp(key_v1.public_key_b64), _fp(key_v2.public_key_b64)
        rotation_distinct = key_v1.public_key_b64 != key_v2.public_key_b64 and fp_v1 != fp_v2

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

        # Case A — old key RETAINED in verificationMethod: HistoricallyAuthorized.
        retained_both = {fp_v1: key_v1.public_key_b64, fp_v2: key_v2.public_key_b64}
        historically_authorized = _historically_authorized(
            receipt_v1, sig_value=sig_v1, content_hash=ch_v1, retained_keys=retained_both
        )

        # Case B — receipt STRIPPED: must fail closed.
        stripped_fail_closed = False
        try:
            _historically_authorized(
                None, sig_value=sig_v1, content_hash=ch_v1, retained_keys=retained_both
            )
        except HistoricalAuthFailed:
            stripped_fail_closed = True

        # Case C — old key REMOVED from the DID document: fails even WITH a
        # matching-intent receipt (documents the producer's retain obligation).
        only_new = {fp_v2: key_v2.public_key_b64}
        removed_key_fail_closed = False
        try:
            _historically_authorized(
                receipt_v1, sig_value=sig_v1, content_hash=ch_v1, retained_keys=only_new
            )
        except HistoricalAuthFailed:
            removed_key_fail_closed = True

        offline_core_ok = (
            rotation_distinct
            and pre_verifies_old
            and new_key_rejects
            and historically_authorized
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
                preview=f"historically_authorized={historically_authorized}; "
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
