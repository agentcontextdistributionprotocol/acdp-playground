"""S30 — lineage-head receipt freshness (RFC-ACDP-0011, ACDP 0.3.0).

``GET /lineages/{id}/current`` answers "what is the newest version?" — but a
plain answer can be replayed or served stale. A head-receipts-profile
registry signs the answer: the **lineage-head receipt** binds
lineage → newest head (``head_ctx_id`` + ``head_version`` + ``head_status``)
at a signed ``as_of`` instant, under the registry's receipt key. The consumer
verifies offline with :meth:`AcdpVerifier.verify_lineage_head_receipt`:
closed parse, the §7 registry/lineage/head bindings against its **own
expectations** (including the authority it *actually fetched from*), the
``as_of`` clock-skew gate, and the signature over the raw wire preimage.
Staleness is **policy, not verification failure**: an old-but-authentic
receipt verifies with ``stale: true``.

Deterministic core (offline). A registry signer (derived from the run seed)
mints head receipts and the consumer proves:

* a fresh receipt verifies and binds ctx_id/version/status (``stale: false``);
* the same receipt evaluated past the freshness window (default 300 s) stays
  ``valid: true`` but flips ``stale: true`` — age is reported, policy decides;
* an ``as_of`` in the consumer's future beyond the skew allowance fails;
* a **replayed pre-supersession receipt** no longer matches the consumer's
  post-supersession head expectations — the §7 step 5 binding rejects it;
* any tamper (``head_status`` flip) breaks the signature.

The live half publishes v1 to registry-a, verifies the real ``/current``
receipt (head = v1), supersedes to v2, and verifies the **fresh** receipt now
binds the new head while the retained v1 receipt fails the new expectations.
Degrades gracefully without a registry.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone

from acdp import AcdpProducer, AcdpVerifier

from acdp_client import AcdpClient, AcdpHTTPError
from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios._receipts import (
    did_document,
    ed25519_jwk_vm,
    mint_lineage_head_receipt,
)
from playground.scenarios.models import (
    LineageEdge,
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s30_head_receipt_freshness",
    name="Lineage-Head Receipt Freshness",
    description="/current answers are registry-signed: the lineage-head "
    "receipt binds the newest ctx_id/version/status at a signed as_of "
    "instant. The consumer verifies the bindings against its own "
    "expectations, ages the receipt (stale is policy, not failure), "
    "rejects future-dated receipts, and — after a supersession — proves "
    "a replayed pre-supersession receipt no longer matches the new head.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "vendor risk register"},
)


def _verify(receipt: dict, expected: dict, doc: str, now: str | None = None) -> dict:
    return json.loads(
        AcdpVerifier.verify_lineage_head_receipt(
            json.dumps(receipt), json.dumps(expected), doc, now
        )
    )


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority
    registry_did = f"did:web:{authority}"
    kid = f"{registry_did}#receipt-key-1"

    # ── Deterministic offline core: minted head receipts. ────────────────
    reg = AcdpProducer.from_seed(
        hashlib.sha256(spec.agent_seed("registry-c-heads") + b":signer").digest(),
        registry_did,
        kid,
    )
    reg_doc = did_document(
        registry_did, current=[ed25519_jwk_vm(kid, registry_did, reg.public_key_b64)]
    )

    lineage_id = "lin:sha256:" + hashlib.sha256(spec.run_id.encode()).hexdigest()
    ctx_a = f"acdp://{authority}/00000030-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    ctx_b = f"acdp://{authority}/00000030-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

    def _mint(head_ctx_id: str, head_version: int, as_of: str) -> dict:
        return mint_lineage_head_receipt(
            reg,
            kid,
            registry_did=registry_did,
            lineage_id=lineage_id,
            head_ctx_id=head_ctx_id,
            head_version=head_version,
            head_status="active",
            as_of=as_of,
        )

    receipt_v1 = _mint(ctx_a, 1, "2026-07-05T09:00:00.000Z")
    receipt_v2 = _mint(ctx_b, 2, "2026-07-05T09:05:00.000Z")

    def _expect(head_ctx_id: str, head_version: int) -> dict:
        return {
            "authority": authority,
            "lineage_id": lineage_id,
            "head_ctx_id": head_ctx_id,
            "head_version": head_version,
            "head_status": "active",
        }

    # (a) Fresh receipt: valid, bound, not stale (30 s old).
    fresh = _verify(receipt_v1, _expect(ctx_a, 1), reg_doc, "2026-07-05T09:00:30.000Z")
    fresh_ok = (
        fresh.get("valid") is True and fresh.get("stale") is False and fresh.get("age_secs") == 30
    )

    # (b) Freshness is policy: the same authentic receipt evaluated 10 min
    #     later still VERIFIES but is flagged stale (default max_age 300 s).
    aged = _verify(receipt_v1, _expect(ctx_a, 1), reg_doc, "2026-07-05T09:10:00.000Z")
    stale_flag_ok = aged.get("valid") is True and aged.get("stale") is True

    # (c) A receipt from the consumer's future (beyond the 120 s skew
    #     allowance) fails verification — not merely stale.
    future = _verify(receipt_v1, _expect(ctx_a, 1), reg_doc, "2026-07-05T08:50:00.000Z")
    future_rejected = future.get("valid") is False

    # (d) Post-supersession: the fresh receipt binds the NEW head; a
    #     replayed pre-supersession receipt fails the head binding.
    v2_bound = _verify(receipt_v2, _expect(ctx_b, 2), reg_doc, "2026-07-05T09:05:30.000Z")
    replayed = _verify(receipt_v1, _expect(ctx_b, 2), reg_doc, "2026-07-05T09:05:30.000Z")
    supersession_binding_ok = v2_bound.get("valid") is True and replayed.get("valid") is False

    # (e) Tamper: flipping head_status after signing breaks the signature.
    tampered = dict(receipt_v1, head_status="expired")
    tamper_rejected = (
        _verify(tampered, _expect(ctx_a, 1), reg_doc, "2026-07-05T09:00:30.000Z").get("valid")
        is False
    )

    offline_core_ok = (
        fresh_ok
        and stale_flag_ok
        and future_rejected
        and supersession_binding_ok
        and tamper_rejected
    )

    await events.put(
        StepEvent(
            type="acdp.verify",
            run_id=spec.run_id,
            ts=datetime.now(timezone.utc).isoformat(),
            agent_id=registry_did,
            title="Lineage-head receipt semantics verified (minted)",
            preview=f"fresh={fresh_ok} stale_flag={stale_flag_ok} "
            f"future_rejected={future_rejected} "
            f"supersession_binding={supersession_binding_ok}",
        )
    )

    # ── Live: /current receipts across a supersession on registry-a. ─────
    title = f"{topic} — head-receipted"
    producer = AcdpProducer.from_seed_did_key(spec.agent_seed("head-producer"))
    client = AcdpClient(settings.registry_a_url, run_id=spec.run_id)
    ctx_v1: str | None = None
    ctx_v2: str | None = None
    live_round_trip = "skipped"
    live_v1_receipt_ok = False
    live_v2_receipt_ok = False
    live_replay_rejected = False
    try:
        registry_pub = settings.receipt_verification_public_key_b64()
        if registry_pub is None:
            raise RuntimeError("no registry receipt key provisioned")

        resp1 = await client.publish(
            producer.build_publish_request(
                title=title,
                context_type="data_snapshot",
                visibility="public",
                summary="v1 — head of a fresh lineage.",
                domain="risk",
                tags=["head-receipts"],
            )
        )
        ctx_v1 = resp1.ctx_id
        live_lineage = resp1.lineage_id
        await events.put(
            StepEvent(
                type="acdp.publish",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx_v1,
                title=f"{title} (v1)",
                preview="did:key → head-receipts registry",
            )
        )

        def _live_expect(head: str, version: int, status: str) -> dict:
            # `authority` is where we ACTUALLY fetched from — compare the
            # client's target, never a response field (RFC-ACDP-0011 §7).
            return {
                "authority": authority,
                "lineage_id": live_lineage,
                "head_ctx_id": head,
                "head_version": version,
                "head_status": status,
                "on_current_endpoint": True,
            }

        cur1 = await client.current(live_lineage)
        receipt1 = cur1.lineage_head_receipt
        if receipt1 is None:
            raise RuntimeError("head-receipts registry served no lineage_head_receipt")
        live_kid = receipt1["signature"]["key_id"]
        live_doc = did_document(
            registry_did, current=[ed25519_jwk_vm(live_kid, registry_did, registry_pub)]
        )
        v1_verdict = _verify(
            receipt1,
            _live_expect(cur1.body.ctx_id, cur1.body.version, cur1.registry_state.status),
            live_doc,
        )
        live_v1_receipt_ok = (
            v1_verdict.get("valid") is True
            and v1_verdict.get("stale") is False
            and cur1.body.ctx_id == ctx_v1
        )

        # Supersede → the fresh /current receipt must bind the NEW head.
        prev_body = json.dumps((await client.retrieve_raw(ctx_v1))["body"])
        resp2 = await client.publish(
            producer.build_supersede_request(
                prev_body,
                summary="v2 — refreshed register.",
                expected_lineage_id=live_lineage,
            )
        )
        ctx_v2 = resp2.ctx_id
        cur2 = await client.current(live_lineage)
        receipt2 = cur2.lineage_head_receipt
        if receipt2 is None:
            raise RuntimeError("post-supersession /current served no lineage_head_receipt")
        v2_expected = _live_expect(cur2.body.ctx_id, cur2.body.version, cur2.registry_state.status)
        v2_verdict = _verify(receipt2, v2_expected, live_doc)
        live_v2_receipt_ok = (
            v2_verdict.get("valid") is True
            and v2_verdict.get("stale") is False
            and cur2.body.ctx_id == ctx_v2
            and cur2.body.version == cur1.body.version + 1
        )

        # Replaying the retained v1 receipt against the new head fails the
        # §7 step 5 head binding.
        replay_verdict = _verify(receipt1, v2_expected, live_doc)
        live_replay_rejected = replay_verdict.get("valid") is False

        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx_v2,
                title="Fresh head receipt binds the new head",
                preview=f"v1_receipt={live_v1_receipt_ok} v2_receipt={live_v2_receipt_ok} "
                f"replay_rejected={live_replay_rejected}",
            )
        )
        live_round_trip = "verified"
    except AcdpHTTPError as e:
        live_round_trip = f"http_{e.status}:{e.code}"
        log.warning("S30 registry round-trip failed: %s", e)
    except Exception as e:  # noqa: BLE001 — no registry: degrade
        live_round_trip = f"unreachable:{type(e).__name__}"
        log.warning("S30 registry round-trip unreachable: %s", e)
    finally:
        await client.aclose()

    live_ok = live_v1_receipt_ok and live_v2_receipt_ok and live_replay_rejected
    degraded = not live_ok

    nodes = []
    edges = []
    if ctx_v1:
        nodes.append(
            LineageNode(
                ctx_id=ctx_v1,
                agent_id=producer.agent_did,
                title=f"{title} (v1)",
                context_type="data_snapshot",
                registry_authority=authority,
                step=1,
            )
        )
    if ctx_v1 and ctx_v2:
        nodes.append(
            LineageNode(
                ctx_id=ctx_v2,
                agent_id=producer.agent_did,
                title=f"{title} (v2)",
                context_type="data_snapshot",
                registry_authority=authority,
                step=2,
            )
        )
        edges.append(LineageEdge(src=ctx_v1, dst=ctx_v2))

    summary = {
        "fresh_ok": fresh_ok,
        "stale_flag_ok": stale_flag_ok,
        "future_rejected": future_rejected,
        "supersession_binding_ok": supersession_binding_ok,
        "tamper_rejected": tamper_rejected,
        "offline_core_ok": offline_core_ok,
        "live_round_trip": live_round_trip,
        "live_v1_receipt_ok": live_v1_receipt_ok,
        "live_v2_receipt_ok": live_v2_receipt_ok,
        "live_replay_rejected": live_replay_rejected,
    }
    if degraded:
        summary["degraded"] = True

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if offline_core_ok else "failed",
        contexts=[c for c in (ctx_v1, ctx_v2) if c],
        lineage_graph=LineageGraph(nodes=nodes, edges=edges),
        summary=summary,
        error=None if offline_core_ok else "lineage-head receipt core failed offline verification",
    )
