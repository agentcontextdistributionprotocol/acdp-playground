"""S32 — producer key-revocation signal & compromise-boundary verification
(RFC-ACDP-0014, ACDP 0.3.0).

Rotation says "stop accepting *new* signatures from this key"; **revocation**
says "signatures from this key are untrustworthy **from time T onward**". A
`key-revocation` context is the scalpel that time-scopes a compromise: it
preserves the pre-T history (still historically authorized) while failing
everything at/after T closed. It reuses the ordinary body machinery — a signed,
permanent, `public`, content-addressed context — so this scenario introduces no
new wire object, only the §4 shape, the §5 trust rules and the §7 consumer
semantics.

Deterministic offline core. A did:web producer holds two keys under one DID —
K1 (`#key-1`, the about-to-be-compromised key) and K2 (`#key-2`, the current
key). K1 publishes a context; the producer then rotates to K2 and publishes a
`key-revocation` context that revokes **K1's fingerprint** with compromise
boundary **T**, signed by K2. The consumer, driving the 0.7.0 SDK surface
(`AcdpVerifier.parse_key_revocation` + `classify_under_revocation`), proves:

* **§5 producer-signed revocation** — the revocation body verifies (content
  hash + Ed25519 signature under K2), and `parse_key_revocation` — given the
  resolved signer fingerprint fp(K2) for the §5 step-2 not-self-signed check —
  classifies it `producer_signed` and surfaces fp(K1) / T.
* **§7 step 2 — before T** — a K1-signed context whose **receipt-attested**
  `created_at` is strictly earlier than T classifies
  `historically_authorized_pre_compromise` (the receipt is verified per
  RFC-ACDP-0010 §8 first; its `key_fingerprint` attests K1 itself).
* **§7 step 3 — at/after T** — the same context with a receipt-attested
  `created_at` ≥ T fails closed regardless of the receipt's validity.
* **§7 step 4 — no verifiable publish time** — with no receipt the context
  cannot be placed relative to T and fails closed (the bare body `created_at`
  is registry-assigned and MUST NOT be used).
* **§5 step 2 — not self-signed** — a revocation of K1 *signed by K1 itself*
  proves only possession of the attacker-held key; `parse_key_revocation`
  rejects it (`RuntimeError`).

The live half publishes a genuine `key-revocation`-typed context to registry-a
(proving a real 0.3.0 registry admits the §4 type + public-visibility shape),
retrieves it, parses it (did:key signers run the not-self-signed check natively
from the body), and — using the **genuine** registry receipt `created_at` of a
victim context — runs the §7 boundary both ways (a boundary after the real
publish time → pre-compromise; before it → fail closed). It degrades gracefully
without a registry, and the canonical K1→K2 single-DID producer-signed rotation
lives in the offline core because the playground's `*.playground.local` did:web
DIDs aren't web-hosted (the S24/S27 constraint).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from acdp import AcdpProducer, AcdpVerifier

from acdp_client import AcdpClient, AcdpHTTPError
from acdp_client.models import StepEvent
from acdp_client.signing import verify_signature

from playground.config import get_settings
from playground.scenarios._factory import did_for
from playground.scenarios._receipts import mint_receipt
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s32_key_revocation",
    name="Producer Key-Revocation Signal",
    description="A producer rotates K1→K2 and publishes a signed key-revocation "
    "context (revoked_key_fingerprint=K1, compromised_since=T). A consumer uses "
    "parse_key_revocation + classify_under_revocation: a K1-signed context with "
    "a receipt-attested created_at before T is historically authorized "
    "(pre-compromise); at/after T or with no receipt it fails closed; a K1-signed "
    "revocation of K1 is rejected (not self-signed) — RFC-ACDP-0014.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "compromise-scoped provenance record"},
)

# The compromise boundary T and the two receipt-attested publish times either
# side of it (aligned with the rev-002 conformance fixture).
BOUNDARY_T = "2026-05-01T00:00:00.000Z"
BEFORE_T = "2026-04-16T10:30:15.123Z"
AFTER_T = "2026-05-03T09:00:00.000Z"


def _authz(revs: list[dict], signer_fp: str, created_at: str | None) -> dict:
    """Consumer §7 classification over VERIFIED revocations."""
    return json.loads(
        AcdpVerifier.classify_under_revocation(json.dumps(revs), signer_fp, created_at)
    )


def _build_revocation_body(
    signer: AcdpProducer,
    *,
    revoked_fingerprint: str,
    compromised_since: str,
    reason: str,
    ctx_id: str,
    authority: str,
) -> dict:
    """A `key-revocation` context body in the §5.7 retrieval layout.

    Built through the ordinary publish-request path (`build_publish_request`
    with `type=key-revocation`, `visibility=public`, the §4 metadata) and then
    dressed with the registry-assigned fields `parse_key_revocation` expects on
    a retrieved body. No new signing construction — a revocation *is* a context.
    """
    raw = signer.build_publish_request(
        title="Key revocation — key-1 compromised",
        context_type="key-revocation",
        visibility="public",
        summary=f"Revocation of {revoked_fingerprint}, compromised since {compromised_since}.",
        acdp_version="0.3.0",
        metadata=json.dumps(
            {
                "revoked_key_fingerprint": revoked_fingerprint,
                "compromised_since": compromised_since,
                "reason": reason,
            }
        ),
    )
    body = json.loads(raw)
    lineage_id = "lin:sha256:" + hashlib.sha256(ctx_id.encode()).hexdigest()
    body.update(
        {
            "ctx_id": ctx_id,
            "lineage_id": lineage_id,
            "origin_registry": authority,
            "created_at": AFTER_T,  # the revocation is published after T
        }
    )
    return body


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority

    # ── Deterministic offline core: K1 publishes, rotate to K2, revoke K1. ─
    did = did_for(authority, "revoking-producer")
    kid_k1, kid_k2 = f"{did}#key-1", f"{did}#key-2"
    seed = spec.agent_seed("revoking-producer")
    key_k1 = AcdpProducer.from_seed(hashlib.sha256(seed + b":k1").digest(), did, kid_k1)
    key_k2 = AcdpProducer.from_seed(hashlib.sha256(seed + b":k2").digest(), did, kid_k2)
    fp_k1 = AcdpVerifier.fingerprint_ed25519_b64(key_k1.public_key_b64)
    fp_k2 = AcdpVerifier.fingerprint_ed25519_b64(key_k2.public_key_b64)
    rotation_distinct = key_k1.public_key_b64 != key_k2.public_key_b64 and fp_k1 != fp_k2

    # The victim context, signed by the (soon-compromised) K1.
    victim_ctx_id = f"acdp://{authority}/00000032-1111-4111-8111-111111111111"
    raw_victim = key_k1.build_publish_request(
        title=f"{topic} — signed by key-1",
        context_type="analysis",
        visibility="public",
        summary="A context signed by the key that is later declared compromised.",
        domain="provenance",
        tags=["revocation", "pre-compromise"],
    )
    req_victim = json.loads(raw_victim)
    ch_victim = req_victim["content_hash"]

    # The revocation context, signed by the CURRENT key K2, revoking K1.
    rev_ctx_id = f"acdp://{authority}/00000032-2222-4222-8222-222222222222"
    rev_body = _build_revocation_body(
        key_k2,
        revoked_fingerprint=fp_k1,
        compromised_since=BOUNDARY_T,
        reason="laptop theft; private key material presumed exfiltrated",
        ctx_id=rev_ctx_id,
        authority=authority,
    )

    # §5.11 body pipeline: the revocation body verifies under K2 before we
    # trust it (parse_key_revocation does NOT verify — the docstring is explicit).
    AcdpVerifier.verify_content_hash(json.dumps(rev_body), rev_body["content_hash"])
    revocation_verified = verify_signature(
        "ed25519", key_k2.public_key_b64, rev_body["signature"]["value"], rev_body["content_hash"]
    )

    # §5: parse + shape-validate. The signer is did:web, so we pass the resolved
    # signer fingerprint fp(K2) for the §5 step-2 not-self-signed check.
    parsed = json.loads(AcdpVerifier.parse_key_revocation(json.dumps(rev_body), fp_k2))
    trust_class_producer_signed = (
        parsed.get("trust_class") == "producer_signed"
        and parsed.get("revoked_key_fingerprint") == fp_k1
        and parsed.get("compromised_since") == BOUNDARY_T
    )

    # A registry receipt attesting the victim's publish-time key (K1). The
    # receipt is what turns the body's unverifiable created_at into a §7 boundary
    # input — verified per RFC-ACDP-0010 §8 before use.
    registry_did = f"did:web:{authority}"
    reg_kid = f"{registry_did}#receipt-key-1"
    reg = AcdpProducer.from_seed(
        hashlib.sha256(spec.agent_seed("registry-a-receipt") + b":signer").digest(),
        registry_did,
        reg_kid,
    )
    victim_lineage = "lin:sha256:" + hashlib.sha256(victim_ctx_id.encode()).hexdigest()

    def _receipt(created_at: str) -> dict:
        return mint_receipt(
            reg,
            reg_kid,
            registry_did=registry_did,
            ctx_id=victim_ctx_id,
            lineage_id=victim_lineage,
            origin_registry=authority,
            created_at=created_at,
            content_hash=ch_victim,
            key_fingerprint=fp_k1,
        )

    def _verified_created_at(receipt: dict) -> str:
        """Verify the receipt per RFC-ACDP-0010 §8 (incl. that it attests fp(K1))
        and return its receipt-attested created_at — the ONLY §7 time input."""
        AcdpVerifier.verify_receipt(
            json.dumps(receipt), reg.public_key_b64, victim_ctx_id, ch_victim, fp_k1
        )
        return receipt["created_at"]

    # §7 step 2 — before T → historically authorized (pre-compromise).
    before_verdict = _authz([parsed], fp_k1, _verified_created_at(_receipt(BEFORE_T)))
    pre_compromise_authorized = (
        before_verdict.get("authorization") == "historically_authorized_pre_compromise"
        and before_verdict.get("boundary") == BOUNDARY_T
    )

    # §7 step 3 — at/after T → fail closed despite a valid receipt.
    after_verdict = _authz([parsed], fp_k1, _verified_created_at(_receipt(AFTER_T)))
    post_compromise_fail_closed = (
        after_verdict.get("authorization") == "none"
        and after_verdict.get("boundary") == BOUNDARY_T
        and bool(after_verdict.get("error"))
    )

    # §7 step 4 — no verifiable publish time → fail closed.
    none_verdict = _authz([parsed], fp_k1, None)
    no_receipt_fail_closed = (
        none_verdict.get("authorization") == "none"
        and none_verdict.get("boundary") == BOUNDARY_T
        and bool(none_verdict.get("error"))
    )

    # §5 step 2 — a revocation of K1 SIGNED BY K1 itself is rejected.
    self_body = _build_revocation_body(
        key_k1,
        revoked_fingerprint=fp_k1,
        compromised_since=BOUNDARY_T,
        reason="self-signed revocation — proves only possession of the compromised key",
        ctx_id=f"acdp://{authority}/00000032-3333-4333-8333-333333333333",
        authority=authority,
    )
    self_signed_rejected = False
    try:
        AcdpVerifier.parse_key_revocation(json.dumps(self_body), fp_k1)
    except RuntimeError:
        self_signed_rejected = True

    offline_core_ok = (
        rotation_distinct
        and revocation_verified
        and trust_class_producer_signed
        and pre_compromise_authorized
        and post_compromise_fail_closed
        and no_receipt_fail_closed
        and self_signed_rejected
    )

    await events.put(
        StepEvent(
            type="acdp.verify",
            run_id=spec.run_id,
            ts=datetime.now(timezone.utc).isoformat(),
            agent_id=did,
            title="Key-revocation boundary verified (offline)",
            preview=f"producer_signed={trust_class_producer_signed} "
            f"pre_compromise={pre_compromise_authorized} "
            f"post_fail_closed={post_compromise_fail_closed} "
            f"self_signed_rejected={self_signed_rejected}",
        )
    )

    # ── Live: publish a real key-revocation context; §7 vs a genuine receipt. ─
    client = AcdpClient(settings.registry_a_url, run_id=spec.run_id)
    live_ctx: str | None = None
    live_round_trip = "skipped"
    live_type_admitted = False
    live_revocation_parsed = False
    live_pre_compromise = False
    live_post_fail_closed = False
    try:
        registry_pub = settings.receipt_verification_public_key_b64()
        if registry_pub is None:
            raise RuntimeError("no registry receipt key provisioned")

        # A victim did:key producer publishes → a genuine receipt-attested time.
        victim = AcdpProducer.from_seed_did_key(spec.agent_seed("live-victim"))
        fp_victim = AcdpVerifier.fingerprint_ed25519_b64(victim.public_key_b64)
        resp_v = await client.publish(
            victim.build_publish_request(
                title=f"{topic} — live victim",
                context_type="data_snapshot",
                visibility="public",
                summary="Published by the key a revocation will name.",
                domain="markets",
                tags=["revocation"],
            )
        )
        victim_live_ctx = resp_v.ctx_id
        full_v = await client.retrieve_raw(victim_live_ctx)
        receipt_v = full_v.get("registry_receipt")
        if receipt_v is None:
            raise RuntimeError("registry served no receipt for the victim context")
        AcdpVerifier.verify_content_hash(json.dumps(full_v["body"]), full_v["body"]["content_hash"])
        AcdpVerifier.verify_receipt(
            json.dumps(receipt_v),
            registry_pub,
            victim_live_ctx,
            full_v["body"]["content_hash"],
            fp_victim,
        )
        t_pub = receipt_v["created_at"]  # the genuine receipt-attested publish time

        # A revoker did:key producer publishes a real key-revocation context
        # naming the victim's fingerprint, with a boundary AFTER the victim's
        # genuine publish time (so the victim is pre-compromise). signer != revoked.
        revoker = AcdpProducer.from_seed_did_key(spec.agent_seed("live-revoker"))
        t_boundary = (
            datetime.strptime(t_pub, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            + timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        raw_rev = revoker.build_publish_request(
            title="Key revocation — live victim key compromised",
            context_type="key-revocation",
            visibility="public",
            summary=f"Revocation of {fp_victim}, compromised since {t_boundary}.",
            acdp_version="0.3.0",
            metadata=json.dumps(
                {
                    "revoked_key_fingerprint": fp_victim,
                    "compromised_since": t_boundary,
                    "reason": "live conformance revocation",
                }
            ),
        )
        resp_r = await client.publish(raw_rev)
        live_ctx = resp_r.ctx_id
        live_type_admitted = True  # the 0.3.0 registry accepted type=key-revocation
        await events.put(
            StepEvent(
                type="acdp.publish",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=revoker.agent_did,
                ctx_id=live_ctx,
                title="key-revocation context published",
                preview="did:key → 0.3.0 registry (type admitted)",
            )
        )

        # Retrieve + parse the real revocation. did:key signer → the not-self-
        # signed check runs natively from the body (no host-resolved fingerprint).
        full_r = await client.retrieve_raw(live_ctx)
        AcdpVerifier.verify_content_hash(json.dumps(full_r["body"]), full_r["body"]["content_hash"])
        live_parsed = json.loads(AcdpVerifier.parse_key_revocation(json.dumps(full_r["body"])))
        live_revocation_parsed = (
            live_parsed.get("trust_class") == "producer_signed"
            and live_parsed.get("revoked_key_fingerprint") == fp_victim
        )

        # §7 against the GENUINE receipt-attested time, both sides of a boundary.
        live_pre = _authz([live_parsed], fp_victim, t_pub)
        live_pre_compromise = (
            live_pre.get("authorization") == "historically_authorized_pre_compromise"
        )
        # Move the boundary to BEFORE the genuine publish time → fail closed.
        earlier = dict(live_parsed, compromised_since=BEFORE_T)
        live_post = _authz([earlier], fp_victim, t_pub)
        live_post_fail_closed = live_post.get("authorization") == "none" and bool(
            live_post.get("error")
        )

        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=revoker.agent_did,
                ctx_id=live_ctx,
                title="Live §7 boundary vs a genuine receipt",
                preview=f"parsed={live_revocation_parsed} pre_compromise={live_pre_compromise} "
                f"post_fail_closed={live_post_fail_closed}",
            )
        )
        live_round_trip = "verified"
    except AcdpHTTPError as e:
        live_round_trip = f"http_{e.status}:{e.code}"
        log.warning("S32 registry round-trip failed: %s", e)
    except Exception as e:  # noqa: BLE001 — no registry: degrade
        live_round_trip = f"unreachable:{type(e).__name__}"
        log.warning("S32 registry round-trip unreachable: %s", e)
    finally:
        await client.aclose()

    live_ok = (
        live_type_admitted
        and live_revocation_parsed
        and live_pre_compromise
        and live_post_fail_closed
    )
    degraded = not live_ok

    nodes = []
    if live_ctx:
        nodes.append(
            LineageNode(
                ctx_id=live_ctx,
                agent_id="did:key (revoker)",
                title="key-revocation context",
                context_type="key-revocation",
                registry_authority=settings.registry_a_authority,
                step=1,
            )
        )

    summary = {
        "producer_did_method": "did:web",
        "revoked_key_fingerprint": fp_k1,
        "compromise_boundary": BOUNDARY_T,
        "rotation_distinct": rotation_distinct,
        "revocation_verified": revocation_verified,
        "trust_class": parsed.get("trust_class"),
        "trust_class_producer_signed": trust_class_producer_signed,
        "pre_compromise_authorized": pre_compromise_authorized,
        "post_compromise_fail_closed": post_compromise_fail_closed,
        "no_receipt_fail_closed": no_receipt_fail_closed,
        "self_signed_rejected": self_signed_rejected,
        "offline_core_ok": offline_core_ok,
        "live_round_trip": live_round_trip,
        "live_type_admitted": live_type_admitted,
        "live_revocation_parsed": live_revocation_parsed,
        "live_pre_compromise": live_pre_compromise,
        "live_post_fail_closed": live_post_fail_closed,
    }
    if degraded:
        summary["degraded"] = True

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if offline_core_ok else "failed",
        contexts=[live_ctx] if live_ctx else [],
        lineage_graph=LineageGraph(nodes=nodes, edges=[]),
        summary=summary,
        error=None if offline_core_ok else "key-revocation core failed offline verification",
    )
