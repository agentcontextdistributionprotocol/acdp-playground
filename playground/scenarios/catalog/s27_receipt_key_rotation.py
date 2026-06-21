"""S27 — registry receipt-key rotation & historical receipt verification.

Closes the *registry-side* half of the RFC-ACDP-0010 §9 key lifecycle (S24
covers the producer side). A registry rotates its **receipt-signing** key:
the retired key MUST stay in the registry DID document's ``verificationMethod``
so every receipt it ever signed keeps verifying, but it leaves
``assertionMethod`` so it can mint no new ones. A consumer holding an old
receipt resolves the signing key the new way — :meth:`AcdpDidDocument.
receipt_key_for_algorithm`, the 0.5.0 SDK primitive — which applies that
lifecycle and reports a distinguishable ``historical`` flag instead of the
strict ``assertionMethod`` gate that producer/auth keys use.

Deterministic core (offline). A registry signs two receipts across a rotation
(``receipt-key-1`` → ``receipt-key-2``) and the consumer resolves each through
the SDK:

* **Historical receipt** — signed by the *retired* key, still in
  ``verificationMethod``: resolves with ``historical=true`` and verifies. The
  consumer reports it ``verified_historical`` — exactly the verdict the control
  plane's receipt-audit mode now emits.
* **Current receipt** — signed by the *current* key: resolves with
  ``historical=false`` and verifies (``verified``).
* **Compromise revocation** — the retired key fully **removed** from
  ``verificationMethod``: resolution fails ``key_not_found`` and the consumer
  fails closed. Full removal (not rotation) is the registry's compromise signal.
* **Algorithm-downgrade defense** — requesting ``ecdsa-p256`` for an Ed25519
  receipt key is rejected ``alg_mismatch`` (RFC-ACDP-0008 §3.9), so a forged
  receipt can't force a weaker check.
* **Binding cross-check** — a historical receipt whose ``content_hash`` no
  longer matches the body is rejected even though its key still resolves.

The live half publishes a real ``did:key`` context to the receipts-profile
registry (registry-c), then resolves the *genuine* registry receipt's signing
key through the same ``receipt_key_for_algorithm`` path (a current key, so
``historical=false``) and verifies it — proving the §9 consumer flow works
against a live registry, not just minted receipts. It degrades gracefully
without a registry (the playground's registry DID isn't web-hosted).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone

from acdp import AcdpDidDocument, AcdpProducer, AcdpVerifier, DidResolutionError

from acdp_client import AcdpClient, AcdpHTTPError
from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios._receipts import did_document, ed25519_jwk_vm, mint_receipt
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s27_receipt_key_rotation",
    name="Registry Receipt-Key Rotation",
    description="A registry rotates its receipt-signing key; a consumer "
    "verifies a historical receipt under the retired key via the SDK's "
    "receipt_key_for_algorithm (historical=true → verified_historical), "
    "and fails closed when the retired key is removed or downgraded.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "long-lived registry attestation"},
)


class ReceiptUnverifiable(RuntimeError):
    """Fail-closed: the receipt's signing key could not be resolved/verified."""


def _verify_via_did(
    receipt: dict,
    doc: AcdpDidDocument,
    *,
    ctx_id: str,
    content_hash: str,
    key_fingerprint: str,
) -> str:
    """Resolve the receipt's signing key from the registry DID document and
    verify the receipt under it.

    Resolution goes through :meth:`AcdpDidDocument.receipt_key_for_algorithm`
    (the §9 lifecycle): a retired-but-retained key resolves with
    ``historical=true``; a removed key raises ``DidResolutionError`` and we
    fail closed. Returns ``"verified_historical"`` or ``"verified"`` to mirror
    the control plane's receipt-audit verdicts.
    """
    sig = receipt["signature"]
    try:
        resolved = doc.receipt_key_for_algorithm(sig["key_id"], sig["algorithm"])
    except DidResolutionError as e:
        raise ReceiptUnverifiable(
            f"receipt key {sig['key_id']} unresolvable: {getattr(e, 'reason', '?')}"
        ) from e
    AcdpVerifier.verify_receipt(
        json.dumps(receipt), resolved["public_key_b64"], ctx_id, content_hash, key_fingerprint
    )
    return "verified_historical" if resolved["historical"] == "true" else "verified"


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_c_authority
    registry_did = f"did:web:{authority}"
    kid_v1, kid_v2 = f"{registry_did}#receipt-key-1", f"{registry_did}#receipt-key-2"

    # ── Deterministic offline core: a registry rotating its receipt key. ──
    # Two registry receipt-signing keys for ONE registry DID, derived
    # deterministically so the run is reproducible.
    seed = spec.agent_seed("registry-c-receipt")
    reg_v1 = AcdpProducer.from_seed(hashlib.sha256(seed + b":v1").digest(), registry_did, kid_v1)
    reg_v2 = AcdpProducer.from_seed(hashlib.sha256(seed + b":v2").digest(), registry_did, kid_v2)

    # The published context the receipts attest (a did:key producer's key
    # fingerprint is what the registry records).
    producer = AcdpProducer.from_seed_did_key(spec.agent_seed("attested-producer"))
    producer_fp = AcdpVerifier.fingerprint_ed25519_b64(producer.public_key_b64)
    ctx_id = f"acdp://{authority}/{spec.run_id[:8]}-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    lineage_id = f"acdp://{authority}/{spec.run_id[:8]}-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    content_hash = "sha256:" + hashlib.sha256(spec.run_id.encode()).hexdigest()

    def _mint(signer: AcdpProducer, key_id: str, created_at: str) -> dict:
        return mint_receipt(
            signer,
            key_id,
            registry_did=registry_did,
            ctx_id=ctx_id,
            lineage_id=lineage_id,
            origin_registry=authority,
            created_at=created_at,
            content_hash=content_hash,
            key_fingerprint=producer_fp,
        )

    historical_receipt = _mint(reg_v1, kid_v1, "2026-01-01T00:00:00.000Z")
    current_receipt = _mint(reg_v2, kid_v2, "2026-06-01T00:00:00.000Z")

    vm_v1 = ed25519_jwk_vm(kid_v1, registry_did, reg_v1.public_key_b64)
    vm_v2 = ed25519_jwk_vm(kid_v2, registry_did, reg_v2.public_key_b64)

    # Post-rotation registry document: v1 retired (verificationMethod only),
    # v2 current (assertionMethod).
    doc_rotated = AcdpDidDocument.parse(
        did_document(registry_did, current=[vm_v2], retired=[vm_v1]), registry_did
    )

    # (a) Historical receipt verifies under the retired key → verified_historical.
    historical_status = _verify_via_did(
        historical_receipt,
        doc_rotated,
        ctx_id=ctx_id,
        content_hash=content_hash,
        key_fingerprint=producer_fp,
    )
    historical_receipt_verified = historical_status == "verified_historical"

    # (b) Current receipt verifies under the current key → verified.
    current_status = _verify_via_did(
        current_receipt,
        doc_rotated,
        ctx_id=ctx_id,
        content_hash=content_hash,
        key_fingerprint=producer_fp,
    )
    current_receipt_verified = current_status == "verified"

    # (c) Compromise revocation: v1 fully removed → fail closed (key_not_found).
    doc_removed = AcdpDidDocument.parse(did_document(registry_did, current=[vm_v2]), registry_did)
    removed_key_fail_closed = False
    try:
        _verify_via_did(
            historical_receipt,
            doc_removed,
            ctx_id=ctx_id,
            content_hash=content_hash,
            key_fingerprint=producer_fp,
        )
    except ReceiptUnverifiable:
        removed_key_fail_closed = True

    # (d) Algorithm-downgrade defense: ask for p256 on an Ed25519 receipt key.
    downgrade_rejected = False
    try:
        doc_rotated.receipt_key_for_algorithm(kid_v1, "ecdsa-p256")
    except DidResolutionError:
        downgrade_rejected = True

    # (e) Binding cross-check: a historical receipt whose body no longer
    #     matches is rejected even though its key still resolves.
    tampered_historical_rejected = False
    try:
        _verify_via_did(
            historical_receipt,
            doc_rotated,
            ctx_id=ctx_id,
            content_hash="sha256:" + "ff" * 32,
            key_fingerprint=producer_fp,
        )
    except Exception:  # noqa: BLE001 — verify_receipt raises on the binding mismatch
        tampered_historical_rejected = True

    offline_core_ok = (
        historical_receipt_verified
        and current_receipt_verified
        and removed_key_fail_closed
        and downgrade_rejected
        and tampered_historical_rejected
    )

    await events.put(
        StepEvent(
            type="acdp.verify",
            run_id=spec.run_id,
            ts=datetime.now(timezone.utc).isoformat(),
            agent_id=registry_did,
            title="Registry receipt-key rotation verified",
            preview=f"historical={historical_status}; current={current_status}; "
            f"removed_fail_closed={removed_key_fail_closed}; "
            f"downgrade_rejected={downgrade_rejected}",
        )
    )

    # ── Live: publish to registry-c, resolve the genuine receipt's key. ──
    title = f"{topic} — receipted"
    client = AcdpClient(settings.registry_c_url, run_id=spec.run_id)
    ctx_published: str | None = None
    live_round_trip = "skipped"
    live_receipt_status = "none"
    live_ok = False
    try:
        raw = producer.build_publish_request(
            title=title,
            context_type="data_snapshot",
            visibility="public",
            summary="Attested by a rotating receipt key.",
            domain="provenance",
            tags=["receipts", "rotation"],
        )
        resp = await client.publish(raw)
        ctx_published = resp.ctx_id
        await events.put(
            StepEvent(
                type="acdp.publish",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx_published,
                title=title,
                preview="did:key → receipts registry",
            )
        )
        full = await client.retrieve_raw(ctx_published)
        body = full["body"]
        receipt = full.get("registry_receipt")
        registry_pub = settings.registry_c_receipt_public_key_b64()
        if receipt is not None and registry_pub is not None:
            echoed_hash = body["content_hash"]
            AcdpVerifier.verify_content_hash(json.dumps(body), echoed_hash)
            # Build the registry's DID document from its current receipt key,
            # keyed by the id the live receipt actually names, then resolve +
            # verify through the §9 path (a current key → historical=false).
            live_kid = receipt["signature"]["key_id"]
            live_vm = ed25519_jwk_vm(live_kid, registry_did, registry_pub)
            live_doc = AcdpDidDocument.parse(
                did_document(registry_did, current=[live_vm]), registry_did
            )
            live_receipt_status = _verify_via_did(
                receipt,
                live_doc,
                ctx_id=ctx_published,
                content_hash=echoed_hash,
                key_fingerprint=producer_fp,
            )
            live_ok = live_receipt_status == "verified"
            live_round_trip = "verified" if live_ok else live_receipt_status
        else:
            live_round_trip = "no_receipt"
    except AcdpHTTPError as e:
        live_round_trip = f"http_{e.status}:{e.code}"
        log.warning("S27 registry round-trip failed: %s", e)
    except Exception as e:  # noqa: BLE001 — no registry: degrade
        live_round_trip = f"unreachable:{type(e).__name__}"
        log.warning("S27 registry round-trip unreachable: %s", e)
    finally:
        await client.aclose()

    degraded = not live_ok

    nodes = []
    if ctx_published:
        nodes.append(
            LineageNode(
                ctx_id=ctx_published,
                agent_id=producer.agent_did,
                title=title,
                context_type="data_snapshot",
                registry_authority=authority,
                step=1,
            )
        )

    summary = {
        "historical_receipt_verified": historical_receipt_verified,
        "historical_status": historical_status,
        "current_receipt_verified": current_receipt_verified,
        "current_status": current_status,
        "removed_key_fail_closed": removed_key_fail_closed,
        "downgrade_rejected": downgrade_rejected,
        "tampered_historical_rejected": tampered_historical_rejected,
        "offline_core_ok": offline_core_ok,
        "live_round_trip": live_round_trip,
        "live_receipt_status": live_receipt_status,
    }
    if degraded:
        summary["degraded"] = True

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if offline_core_ok else "failed",
        contexts=[ctx_published] if ctx_published else [],
        lineage_graph=LineageGraph(nodes=nodes, edges=[]),
        summary=summary,
        error=None if offline_core_ok else "registry receipt-key rotation core failed",
    )
