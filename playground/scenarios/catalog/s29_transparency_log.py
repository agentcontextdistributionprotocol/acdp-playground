"""S29 — transparency log: inclusion + consistency proofs (RFC-ACDP-0012).

A transparency-log-profile registry appends a Merkle leaf per accepted
publish and serves a signed tree head (``/log/checkpoint``) plus inclusion
and consistency proofs (``/log/proof``). The consumer's obligations are all
offline SDK calls:

* **verify the checkpoint signature** against the registry's receipt key
  (``verify_log_checkpoint`` — closed parse, log_id pin, clock skew);
* **rebuild the leaf itself** from the *verified* publish receipt
  (``build_log_leaf`` — never trust a registry-echoed leaf) and fold the
  audit path to the checkpoint root (``verify_log_inclusion``);
* after the tree grows, prove the earlier tree is a **prefix** of the later
  one against the consumer's own *retained root*
  (``verify_log_consistency`` — the history-rewrite detector).

Deterministic core (offline). A registry signer (derived from the run seed)
mints two receipts; the scenario rebuilds their leaves, computes roots with
:class:`AcdpMerkle`, mints checkpoints at sizes 1 and 2, and proves:
checkpoint signature, inclusion at both sizes, consistency 1→2 against the
retained size-1 root, and that every tampered artifact — flipped inclusion
path, flipped checkpoint root, rewritten history, substituted embedded
checkpoint — fails closed with the ``invalid_log_proof`` taxonomy.

The live half publishes twice to registry-a, verifying the real
``/log/checkpoint`` and ``/log/proof?ctx_id=`` artifacts between publishes
and the real consistency proof across the two observed tree sizes. Degrades
gracefully without a registry.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime

from acdp import AcdpMerkle, AcdpProducer, AcdpVerifier

from acdp_client import AcdpClient, AcdpHTTPError
from acdp_client.models import StepEvent
from playground.config import get_settings
from playground.scenarios._receipts import (
    did_document,
    ed25519_jwk_vm,
    mint_log_checkpoint,
    mint_receipt,
)
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s29_transparency_log",
    name="Transparency Log Proofs",
    description="Publishes are logged in a Merkle tree: the consumer verifies "
    "the signed checkpoint, rebuilds the leaf from the verified receipt "
    "and folds the inclusion path, then — after the tree grows — proves "
    "consistency against its own retained root. Every tampered proof "
    "fails closed as invalid_log_proof.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "audit-logged market snapshot"},
)


def _verdict(raw: str) -> dict:
    return json.loads(raw)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority
    registry_did = f"did:web:{authority}"
    kid = f"{registry_did}#receipt-key-1"
    log_id = f"{registry_did}/log/1"

    # ── Deterministic offline core: a two-entry log, minted + proven. ────
    reg = AcdpProducer.from_seed(
        hashlib.sha256(spec.agent_seed("registry-c-log") + b":signer").digest(),
        registry_did,
        kid,
    )
    reg_doc = did_document(
        registry_did, current=[ed25519_jwk_vm(kid, registry_did, reg.public_key_b64)]
    )

    producer = AcdpProducer.from_seed_did_key(spec.agent_seed("logged-producer"))
    producer_fp = AcdpVerifier.fingerprint_ed25519_b64(producer.public_key_b64)
    lineage_id = "lin:sha256:" + hashlib.sha256(spec.run_id.encode()).hexdigest()

    def _receipt(n: int, created_at: str) -> dict:
        return mint_receipt(
            reg,
            kid,
            registry_did=registry_did,
            ctx_id=f"acdp://{authority}/0000000{n}-0000-4000-8000-000000000000",
            lineage_id=lineage_id,
            origin_registry=authority,
            created_at=created_at,
            content_hash="sha256:" + hashlib.sha256(f"{spec.run_id}:{n}".encode()).hexdigest(),
            key_fingerprint=producer_fp,
        )

    rcpt0 = _receipt(0, "2026-07-05T08:00:00.000Z")
    rcpt1 = _receipt(1, "2026-07-05T08:30:00.000Z")

    # §9.1 step 1: rebuild each leaf from the (minted, hence trusted here)
    # receipt — the live half runs verify_receipt first.
    leaf0 = AcdpVerifier.build_log_leaf(json.dumps(rcpt0))
    leaf1 = AcdpVerifier.build_log_leaf(json.dumps(rcpt1))
    h0, h1 = AcdpMerkle.leaf_hash(leaf0), AcdpMerkle.leaf_hash(leaf1)
    root1 = AcdpMerkle.root_hash(json.dumps([h0]))
    root2 = AcdpMerkle.root_hash(json.dumps([h0, h1]))
    ckpt1 = mint_log_checkpoint(
        reg,
        kid,
        log_id=log_id,
        tree_size=1,
        root_hash=root1,
        timestamp="2026-07-05T08:10:00.000Z",
    )
    ckpt2 = mint_log_checkpoint(
        reg,
        kid,
        log_id=log_id,
        tree_size=2,
        root_hash=root2,
        timestamp="2026-07-05T08:40:00.000Z",
    )

    # (a) Checkpoint signatures verify against the registry DID document
    #     (with the §7.4 log_id pin).
    ck1_v = _verdict(
        AcdpVerifier.verify_log_checkpoint(
            json.dumps(ckpt1), reg_doc, log_id, "2026-07-05T08:10:05.000Z"
        )
    )
    ck2_v = _verdict(
        AcdpVerifier.verify_log_checkpoint(
            json.dumps(ckpt2), reg_doc, log_id, "2026-07-05T08:40:05.000Z"
        )
    )
    checkpoints_verified = ck1_v.get("valid") is True and ck2_v.get("valid") is True

    # (b) Inclusion: leaf 0 at size 1 (empty path), leaf 1 at size 2.
    inc0 = {"log_id": log_id, "leaf_index": 0, "tree_size": 1, "inclusion_path": []}
    inc1 = {"log_id": log_id, "leaf_index": 1, "tree_size": 2, "inclusion_path": [h0]}
    inc0_v = _verdict(AcdpVerifier.verify_log_inclusion(json.dumps(inc0), json.dumps(ckpt1), leaf0))
    inc1_v = _verdict(AcdpVerifier.verify_log_inclusion(json.dumps(inc1), json.dumps(ckpt2), leaf1))
    inclusion_verified = (
        inc0_v.get("valid") is True
        and inc0_v.get("leaf_hash") == h0
        and inc1_v.get("valid") is True
        and inc1_v.get("leaf_hash") == h1
    )

    # (c) Consistency 1→2 against the RETAINED size-1 root — retaining the
    #     root is the whole point (§9.2).
    con = {
        "log_id": log_id,
        "first_tree_size": 1,
        "second_tree_size": 2,
        "consistency_path": [h1],
    }
    con_v = _verdict(AcdpVerifier.verify_log_consistency(json.dumps(con), json.dumps(ckpt2), root1))
    consistency_verified = con_v.get("valid") is True

    # (d) Fail-closed taxonomy: every tampered artifact is invalid_log_proof.
    bad_path = _verdict(
        AcdpVerifier.verify_log_inclusion(
            json.dumps(dict(inc1, inclusion_path=["sha256:" + "0" * 64])),
            json.dumps(ckpt2),
            leaf1,
        )
    )
    bad_root = _verdict(
        AcdpVerifier.verify_log_checkpoint(
            json.dumps(dict(ckpt2, root_hash="sha256:" + "f" * 64)),
            reg_doc,
            log_id,
            "2026-07-05T08:40:05.000Z",
        )
    )
    # A retained root the path cannot reach = logged-history rewrite.
    rewrite = _verdict(
        AcdpVerifier.verify_log_consistency(
            json.dumps(con), json.dumps(ckpt2), "sha256:" + "e" * 64
        )
    )
    # A proof quietly embedding a DIFFERENT checkpoint must be refused.
    substituted = _verdict(
        AcdpVerifier.verify_log_inclusion(
            json.dumps(dict(inc1, log_checkpoint=dict(ckpt2, tree_size=3))),
            json.dumps(ckpt2),
            leaf1,
        )
    )
    tamper_fail_closed = all(
        v.get("valid") is False and v.get("code") == "invalid_log_proof"
        for v in (bad_path, bad_root, rewrite, substituted)
    )

    offline_core_ok = (
        checkpoints_verified and inclusion_verified and consistency_verified and tamper_fail_closed
    )

    await events.put(
        StepEvent(
            type="acdp.verify",
            run_id=spec.run_id,
            ts=datetime.now(UTC).isoformat(),
            agent_id=registry_did,
            title="Transparency-log proofs verified (minted log)",
            preview=f"checkpoints={checkpoints_verified} inclusion={inclusion_verified} "
            f"consistency={consistency_verified} tamper_fail_closed={tamper_fail_closed}",
        )
    )

    # ── Live: publish twice, verify the real /log artifacts in between. ──
    title = f"{topic} — logged"
    client = AcdpClient(settings.registry_a_url, run_id=spec.run_id)
    ctx1: str | None = None
    ctx2: str | None = None
    live_round_trip = "skipped"
    live_checkpoint_verified = False
    live_inclusion_verified = False
    live_consistency_verified = False
    live_tamper_fail_closed = False
    try:
        registry_pub = settings.receipt_verification_public_key_b64()
        if registry_pub is None:
            raise RuntimeError("no registry receipt key provisioned")

        resp1 = await client.publish(
            producer.build_publish_request(
                title=title,
                context_type="data_snapshot",
                visibility="public",
                summary="First logged publish.",
                domain="markets",
                tags=["transparency-log"],
            )
        )
        ctx1 = resp1.ctx_id
        await events.put(
            StepEvent(
                type="acdp.publish",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx1,
                title=title,
                preview="did:key → transparency-log registry",
            )
        )

        # Checkpoint A — verify signature vs the registry's receipt key. The
        # DID document is built from the shared seed because the playground's
        # *.playground.local registry DID isn't web-hosted (see S22/S27).
        ckpt_a = await client.log_checkpoint()
        live_kid = ckpt_a["signature"]["key_id"]
        live_doc = did_document(
            registry_did, current=[ed25519_jwk_vm(live_kid, registry_did, registry_pub)]
        )
        live_log_id = ckpt_a["log_id"]
        ck_a_v = _verdict(
            AcdpVerifier.verify_log_checkpoint(json.dumps(ckpt_a), live_doc, live_log_id)
        )
        size_a, root_a = ckpt_a["tree_size"], ckpt_a["root_hash"]

        # Inclusion of ctx1: verify the receipt, rebuild the leaf, verify the
        # proof against the proof's own (signature-checked) checkpoint.
        full1 = await client.retrieve_raw(ctx1)
        receipt1 = full1["registry_receipt"]
        AcdpVerifier.verify_content_hash(json.dumps(full1["body"]), full1["body"]["content_hash"])
        AcdpVerifier.verify_receipt(
            json.dumps(receipt1),
            registry_pub,
            ctx1,
            full1["body"]["content_hash"],
            AcdpVerifier.fingerprint_ed25519_b64(producer.public_key_b64),
        )
        live_leaf = AcdpVerifier.build_log_leaf(json.dumps(receipt1))
        proof1 = await client.log_proof(ctx_id=ctx1)
        proof_ckpt = proof1.get("log_checkpoint", ckpt_a)
        pc_v = _verdict(
            AcdpVerifier.verify_log_checkpoint(json.dumps(proof_ckpt), live_doc, live_log_id)
        )
        inc_v = _verdict(
            AcdpVerifier.verify_log_inclusion(json.dumps(proof1), json.dumps(proof_ckpt), live_leaf)
        )
        live_checkpoint_verified = ck_a_v.get("valid") is True and pc_v.get("valid") is True
        live_inclusion_verified = inc_v.get("valid") is True
        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx1,
                title="Log inclusion verified",
                preview=f"tree_size={proof_ckpt.get('tree_size')} "
                f"leaf_hash={inc_v.get('leaf_hash', '')[:23]}…",
            )
        )

        # Grow the tree, then prove consistency size_a → size_b against the
        # retained root_a.
        resp2 = await client.publish(
            producer.build_publish_request(
                title=f"{title} (follow-up)",
                context_type="data_snapshot",
                visibility="public",
                summary="Second logged publish — grows the tree.",
                domain="markets",
                tags=["transparency-log"],
            )
        )
        ctx2 = resp2.ctx_id
        ckpt_b = await client.log_checkpoint()
        size_b = ckpt_b["tree_size"]
        ck_b_v = _verdict(
            AcdpVerifier.verify_log_checkpoint(json.dumps(ckpt_b), live_doc, live_log_id)
        )
        consistency = await client.log_proof(first=size_a, second=size_b)
        # The registry mints a FRESH checkpoint object (new timestamp +
        # signature) per response, so the proof's embedded checkpoint is not
        # byte-equal to the separately fetched ckpt_b — verify the embedded
        # one's signature and use it (same §9.1 step 3 discipline as the
        # inclusion flow); ckpt_b independently pins the tree size.
        con_ckpt = consistency.get("log_checkpoint", ckpt_b)
        con_ckpt_v = _verdict(
            AcdpVerifier.verify_log_checkpoint(json.dumps(con_ckpt), live_doc, live_log_id)
        )
        con_live_v = _verdict(
            AcdpVerifier.verify_log_consistency(
                json.dumps(consistency), json.dumps(con_ckpt), root_a
            )
        )
        live_consistency_verified = (
            ck_b_v.get("valid") is True
            and con_ckpt_v.get("valid") is True
            and con_ckpt["tree_size"] == size_b
            and size_b > size_a
            and con_live_v.get("valid") is True
        )

        # Fail-closed against the LIVE artifacts too: a rewritten retained
        # root must be detected as invalid_log_proof.
        live_rewrite = _verdict(
            AcdpVerifier.verify_log_consistency(
                json.dumps(consistency), json.dumps(con_ckpt), "sha256:" + "e" * 64
            )
        )
        live_tamper_fail_closed = (
            live_rewrite.get("valid") is False and live_rewrite.get("code") == "invalid_log_proof"
        )
        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx2,
                title="Log consistency verified",
                preview=f"{size_a}→{size_b} against retained root",
            )
        )
        live_round_trip = "verified"
    except AcdpHTTPError as e:
        live_round_trip = f"http_{e.status}:{e.code}"
        log.warning("S29 registry round-trip failed: %s", e)
    except Exception as e:  # noqa: BLE001 — no registry: degrade
        live_round_trip = f"unreachable:{type(e).__name__}"
        log.warning("S29 registry round-trip unreachable: %s", e)
    finally:
        await client.aclose()

    live_ok = (
        live_checkpoint_verified
        and live_inclusion_verified
        and live_consistency_verified
        and live_tamper_fail_closed
    )
    degraded = not live_ok

    nodes = [
        LineageNode(
            ctx_id=c,
            agent_id=producer.agent_did,
            title=title if i == 1 else f"{title} (follow-up)",
            context_type="data_snapshot",
            registry_authority=authority,
            step=i,
        )
        for i, c in enumerate((ctx1, ctx2), start=1)
        if c
    ]

    summary = {
        "checkpoints_verified": checkpoints_verified,
        "inclusion_verified": inclusion_verified,
        "consistency_verified": consistency_verified,
        "tamper_fail_closed": tamper_fail_closed,
        "offline_core_ok": offline_core_ok,
        "live_round_trip": live_round_trip,
        "live_checkpoint_verified": live_checkpoint_verified,
        "live_inclusion_verified": live_inclusion_verified,
        "live_consistency_verified": live_consistency_verified,
        "live_tamper_fail_closed": live_tamper_fail_closed,
    }
    if degraded:
        summary["degraded"] = True

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if offline_core_ok else "failed",
        contexts=[c for c in (ctx1, ctx2) if c],
        lineage_graph=LineageGraph(nodes=nodes, edges=[]),
        summary=summary,
        error=None if offline_core_ok else "transparency-log core failed offline verification",
    )
