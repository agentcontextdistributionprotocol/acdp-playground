"""S31 — transparency-log witness cosigning end to end (RFC-ACDP-0015).

A transparency-log checkpoint (RFC-ACDP-0012 §7) is a signed tree head — but
a *single* registry signature only proves the registry is internally
consistent, not that it isn't split-viewing (showing different logs to
different consumers). RFC-ACDP-0015 closes that gap with **witness
cosignatures**: an independent party observes a checkpoint, discharges the §7
obligation (verify the checkpoint's own signature and its consistency against
a retained prior head — a witness must *check before it cosigns*), then mints
its OWN Ed25519 cosignature over the checkpoint's identity-bearing tuple. A
consumer that requires an N-witnessed quorum can no longer be split-viewed by
the registry alone.

This scenario proves the full RFC-0015 loop with the playground itself acting
as an **independent witness** (the PLAYGROUND-AS-WITNESS pattern — self-
contained, no control-plane witness required), all through the 0.7.0 SDK
surface (``AcdpVerifier.build_witness_cosignature`` /
``verify_witness_cosignature`` / ``evaluate_witness_quorum``):

1. **checkpoint** — a registry signer mints a signed checkpoint the witness
   observes; its signature verifies under the registry DID document
   (``verify_log_checkpoint``, the §7 obligation part 1).
2. **§7 obligation** — before cosigning size 2 the witness verifies the log's
   *consistency* 1→2 against a retained size-1 root (``verify_log_consistency``
   — a witness that cosigns without checking history is worthless).
3. **witness mint** — a fresh Ed25519 witness key (``did:key`` witness DID, so
   no hosting is needed) cosigns the checkpoint's ``{log_id, tree_size,
   root_hash, timestamp}`` subset (``build_witness_cosignature``).
4. **consumer verify + quorum** — the cosignature verifies against the
   witness's DID document and the consumer's independently-held checkpoint
   (``verify_witness_cosignature``), and an N-witnessed quorum report over it
   meets a ``min_witnesses=1`` policy (``evaluate_witness_quorum``).
5. **binding-detects-lies** — a cosignature over a *tampered* root (the
   witness attesting to a root that isn't the real checkpoint's) is refused as
   ``invalid_witness_cosignature`` at the §8 step-4 checkpoint binding, both
   directly and by failing to count toward the quorum.

The live half publishes twice to registry-c (transparency-log profile),
verifies the real ``/log/checkpoint`` and the real consistency proof across
the two observed tree sizes, then cosigns the *live* checkpoint as a witness
and runs the same verify + quorum + tamper assertions against it. Degrades
gracefully without a registry — the deterministic core is the required proof.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone

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
    id="s31_witness_cosigning",
    name="Transparency-Log Witness Cosigning",
    description="An independent witness discharges the §7 obligation (checkpoint "
    "signature + consistency against a retained root), then cosigns the "
    "checkpoint with its own did:key. A consumer verifies the cosignature "
    "and evaluates an N-witnessed quorum; a cosignature over a tampered root "
    "fails closed as invalid_witness_cosignature (RFC-ACDP-0015).",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "witness-cosigned market snapshot"},
)

# The witness signing-key DID URL convention (RFC-ACDP-0015 §5/§9): the mint
# derives "<witness_did>#witness-key-1", so the witness DID document must carry
# a verification method with exactly that id.
WITNESS_KEY_FRAGMENT = "witness-key-1"


def _verdict(raw: str) -> dict:
    return json.loads(raw)


def _witnessed_subset(checkpoint: dict) -> dict:
    """The identity-bearing subset a witness cosigns (closed §5 schema)."""
    return {
        "log_id": checkpoint["log_id"],
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"],
        "timestamp": checkpoint["timestamp"],
    }


def _witness_identity(seed: bytes) -> tuple[str, str, str]:
    """Mint a fresh witness identity from ``seed``.

    Returns ``(witness_did, witness_seed_hex, witness_did_document_json)``.
    The witness DID is a ``did:key`` (its Ed25519 public key is carried in the
    DID itself — no hosting, no SSRF surface), and the DID document exposes the
    §5/§9 ``#witness-key-1`` verification method the mint signs under.
    """
    wp = AcdpProducer.from_seed_did_key(seed)
    witness_did = wp.agent_did
    doc = did_document(
        witness_did,
        current=[
            ed25519_jwk_vm(f"{witness_did}#{WITNESS_KEY_FRAGMENT}", witness_did, wp.public_key_b64)
        ],
    )
    return witness_did, seed.hex(), doc


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_c_authority
    registry_did = f"did:web:{authority}"
    kid = f"{registry_did}#receipt-key-1"
    log_id = f"{registry_did}/log/1"

    # ── Deterministic offline core: a two-entry log, cosigned + proven. ──
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
    leaf0 = AcdpVerifier.build_log_leaf(json.dumps(rcpt0))
    leaf1 = AcdpVerifier.build_log_leaf(json.dumps(rcpt1))
    h0, h1 = AcdpMerkle.leaf_hash(leaf0), AcdpMerkle.leaf_hash(leaf1)
    root1 = AcdpMerkle.root_hash(json.dumps([h0]))
    root2 = AcdpMerkle.root_hash(json.dumps([h0, h1]))
    ckpt2 = mint_log_checkpoint(
        reg, kid, log_id=log_id, tree_size=2, root_hash=root2, timestamp="2026-07-05T08:40:00.000Z"
    )

    # ── §7 witness obligation: a witness must CHECK before it cosigns. ───
    # (1) the checkpoint's own signature verifies (§7 part 1);
    ck2_v = _verdict(
        AcdpVerifier.verify_log_checkpoint(
            json.dumps(ckpt2), reg_doc, log_id, "2026-07-05T08:40:05.000Z"
        )
    )
    checkpoint_verified = ck2_v.get("valid") is True
    # (2) consistency 1→2 against the retained size-1 root (§7 part 2) — a
    #     witness that cosigns a checkpoint it never proved consistent with the
    #     history it already observed is worthless.
    con = {"log_id": log_id, "first_tree_size": 1, "second_tree_size": 2, "consistency_path": [h1]}
    con_v = _verdict(AcdpVerifier.verify_log_consistency(json.dumps(con), json.dumps(ckpt2), root1))
    consistency_verified = con_v.get("valid") is True
    obligation_ok = checkpoint_verified and consistency_verified

    # ── Witness mint: a FRESH did:key witness cosigns the checkpoint. ────
    witness_did, witness_seed_hex, witness_doc = _witness_identity(
        hashlib.sha256(spec.agent_seed("independent-witness") + b":witness").digest()
    )
    witnessed_at = "2026-07-05T08:40:10.000Z"
    cosig = AcdpVerifier.build_witness_cosignature(
        json.dumps(_witnessed_subset(ckpt2)), witness_did, witness_seed_hex, witnessed_at
    )
    now = "2026-07-05T08:41:00.000Z"

    # ── Consumer verify: the cosignature verifies against the witness DID
    #    document AND the consumer's independently-held checkpoint (§8). ──
    cosig_v = _verdict(
        AcdpVerifier.verify_witness_cosignature(cosig, witness_doc, json.dumps(ckpt2), now)
    )
    cosig_verified = cosig_v.get("valid") is True and cosig_v.get("witness_id") == witness_did

    # ── Consumer quorum: 1-witnessed, meets a min_witnesses=1 policy. ────
    quorum = _verdict(
        AcdpVerifier.evaluate_witness_quorum(
            json.dumps([json.loads(cosig)]),
            json.dumps(ckpt2),
            json.dumps([witness_did]),
            json.dumps({witness_did: json.loads(witness_doc)}),
            json.dumps({"min_witnesses": 1}),
            now,
        )
    )
    quorum_ok = (
        quorum.get("witnessed_count") == 1
        and quorum.get("meets_quorum") is True
        and quorum.get("witnesses") == [witness_did]
        and quorum.get("fresh_witnessed_count") == 1
        and quorum.get("meets_fresh_quorum") is True
    )

    # ── binding-detects-lies: a cosignature over a TAMPERED root is refused
    #    at the §8 step-4 checkpoint binding. The witness signature is itself
    #    valid — the point is the consumer's real checkpoint doesn't match. ─
    tampered_root = "sha256:" + "f" * 64
    tampered_subset = dict(_witnessed_subset(ckpt2), root_hash=tampered_root)
    lie_cosig = AcdpVerifier.build_witness_cosignature(
        json.dumps(tampered_subset), witness_did, witness_seed_hex, witnessed_at
    )
    lie_v = _verdict(
        AcdpVerifier.verify_witness_cosignature(lie_cosig, witness_doc, json.dumps(ckpt2), now)
    )
    lie_direct_rejected = (
        lie_v.get("valid") is False and lie_v.get("code") == "invalid_witness_cosignature"
    )
    # And it earns no quorum credit: 0-witnessed, does not meet quorum.
    lie_quorum = _verdict(
        AcdpVerifier.evaluate_witness_quorum(
            json.dumps([json.loads(lie_cosig)]),
            json.dumps(ckpt2),
            json.dumps([witness_did]),
            json.dumps({witness_did: json.loads(witness_doc)}),
            json.dumps({"min_witnesses": 1}),
            now,
        )
    )
    lie_quorum_rejected = (
        lie_quorum.get("witnessed_count") == 0 and lie_quorum.get("meets_quorum") is False
    )
    tamper_fail_closed = lie_direct_rejected and lie_quorum_rejected

    offline_core_ok = obligation_ok and cosig_verified and quorum_ok and tamper_fail_closed

    await events.put(
        StepEvent(
            type="acdp.verify",
            run_id=spec.run_id,
            ts=datetime.now(timezone.utc).isoformat(),
            agent_id=witness_did,
            title="Witness cosignature minted + quorum met (offline)",
            preview=f"obligation={obligation_ok} cosig_verified={cosig_verified} "
            f"quorum={quorum_ok} tamper_fail_closed={tamper_fail_closed}",
        )
    )

    # ── Live: publish twice, verify the real /log artifacts, cosign live. ─
    title = f"{topic} — witnessed"
    client = AcdpClient(settings.registry_c_url, run_id=spec.run_id)
    ctx1: str | None = None
    ctx2: str | None = None
    live_round_trip = "skipped"
    live_obligation_ok = False
    live_cosig_verified = False
    live_quorum_ok = False
    live_tamper_fail_closed = False
    try:
        registry_pub = settings.registry_c_receipt_public_key_b64()
        if registry_pub is None:
            raise RuntimeError("no registry receipt key provisioned")

        resp1 = await client.publish(
            producer.build_publish_request(
                title=title,
                context_type="data_snapshot",
                visibility="public",
                summary="First witnessed publish.",
                domain="markets",
                tags=["witness-cosigning"],
            )
        )
        ctx1 = resp1.ctx_id
        await events.put(
            StepEvent(
                type="acdp.publish",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx1,
                title=title,
                preview="did:key → transparency-log registry",
            )
        )

        # Checkpoint A — verify signature vs the registry's receipt key. The
        # DID document is built from the shared seed because the playground's
        # *.playground.local registry DID isn't web-hosted (see S22/S27/S29).
        ckpt_a = await client.log_checkpoint()
        live_kid = ckpt_a["signature"]["key_id"]
        live_doc = did_document(
            registry_did, current=[ed25519_jwk_vm(live_kid, registry_did, registry_pub)]
        )
        live_log_id = ckpt_a["log_id"]
        size_a, root_a = ckpt_a["tree_size"], ckpt_a["root_hash"]

        # Grow the tree, then re-fetch the checkpoint the witness will cosign.
        resp2 = await client.publish(
            producer.build_publish_request(
                title=f"{title} (follow-up)",
                context_type="data_snapshot",
                visibility="public",
                summary="Second witnessed publish — grows the tree.",
                domain="markets",
                tags=["witness-cosigning"],
            )
        )
        ctx2 = resp2.ctx_id
        ckpt_b = await client.log_checkpoint()
        size_b = ckpt_b["tree_size"]

        # §7 obligation part 1: the checkpoint's own signature verifies.
        ck_b_v = _verdict(
            AcdpVerifier.verify_log_checkpoint(json.dumps(ckpt_b), live_doc, live_log_id)
        )
        # §7 obligation part 2: consistency size_a → size_b against the
        # retained root_a (the witness proves history before cosigning). The
        # registry mints a fresh checkpoint per response, so verify the proof's
        # embedded (signature-checked) checkpoint and use it.
        consistency = await client.log_proof(first=size_a, second=size_b)
        con_ckpt = consistency.get("log_checkpoint", ckpt_b)
        con_ckpt_v = _verdict(
            AcdpVerifier.verify_log_checkpoint(json.dumps(con_ckpt), live_doc, live_log_id)
        )
        con_live_v = _verdict(
            AcdpVerifier.verify_log_consistency(
                json.dumps(consistency), json.dumps(con_ckpt), root_a
            )
        )
        live_obligation_ok = (
            ck_b_v.get("valid") is True
            and con_ckpt_v.get("valid") is True
            and con_ckpt["tree_size"] == size_b
            and size_b > size_a
            and con_live_v.get("valid") is True
        )

        # Witness mint over the LIVE checkpoint the witness just proved.
        live_witness_did, live_witness_seed_hex, live_witness_doc = _witness_identity(
            hashlib.sha256(spec.agent_seed("independent-witness") + b":live-witness").digest()
        )
        live_cosig = AcdpVerifier.build_witness_cosignature(
            json.dumps(_witnessed_subset(con_ckpt)),
            live_witness_did,
            live_witness_seed_hex,
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        )
        live_cosig_v = _verdict(
            AcdpVerifier.verify_witness_cosignature(
                live_cosig, live_witness_doc, json.dumps(con_ckpt)
            )
        )
        live_cosig_verified = (
            live_cosig_v.get("valid") is True and live_cosig_v.get("witness_id") == live_witness_did
        )
        live_quorum = _verdict(
            AcdpVerifier.evaluate_witness_quorum(
                json.dumps([json.loads(live_cosig)]),
                json.dumps(con_ckpt),
                json.dumps([live_witness_did]),
                json.dumps({live_witness_did: json.loads(live_witness_doc)}),
                json.dumps({"min_witnesses": 1}),
            )
        )
        live_quorum_ok = (
            live_quorum.get("witnessed_count") == 1 and live_quorum.get("meets_quorum") is True
        )

        # binding-detects-lies against the LIVE checkpoint too.
        live_lie = AcdpVerifier.build_witness_cosignature(
            json.dumps(dict(_witnessed_subset(con_ckpt), root_hash="sha256:" + "e" * 64)),
            live_witness_did,
            live_witness_seed_hex,
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        )
        live_lie_v = _verdict(
            AcdpVerifier.verify_witness_cosignature(
                live_lie, live_witness_doc, json.dumps(con_ckpt)
            )
        )
        live_tamper_fail_closed = (
            live_lie_v.get("valid") is False
            and live_lie_v.get("code") == "invalid_witness_cosignature"
        )

        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=live_witness_did,
                ctx_id=ctx2,
                title="Live checkpoint cosigned + quorum met",
                preview=f"{size_a}→{size_b} obligation={live_obligation_ok} "
                f"cosig={live_cosig_verified} quorum={live_quorum_ok}",
            )
        )
        live_round_trip = "verified"
    except AcdpHTTPError as e:
        live_round_trip = f"http_{e.status}:{e.code}"
        log.warning("S31 registry round-trip failed: %s", e)
    except Exception as e:  # noqa: BLE001 — no registry: degrade
        live_round_trip = f"unreachable:{type(e).__name__}"
        log.warning("S31 registry round-trip unreachable: %s", e)
    finally:
        await client.aclose()

    live_ok = (
        live_obligation_ok and live_cosig_verified and live_quorum_ok and live_tamper_fail_closed
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
        "witness_did_method": "did:key",
        "witness_did": witness_did,
        "checkpoint_verified": checkpoint_verified,
        "consistency_verified": consistency_verified,
        "obligation_ok": obligation_ok,
        "cosig_verified": cosig_verified,
        "quorum_ok": quorum_ok,
        "witnessed_count": quorum.get("witnessed_count"),
        "meets_quorum": quorum.get("meets_quorum"),
        "tamper_fail_closed": tamper_fail_closed,
        "offline_core_ok": offline_core_ok,
        "live_round_trip": live_round_trip,
        "live_obligation_ok": live_obligation_ok,
        "live_cosig_verified": live_cosig_verified,
        "live_quorum_ok": live_quorum_ok,
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
        error=None if offline_core_ok else "witness-cosigning core failed offline verification",
    )
