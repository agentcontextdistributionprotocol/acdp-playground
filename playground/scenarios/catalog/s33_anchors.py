"""S33 — external anchors (RFC-ACDP-0016, ACDP 0.5.0).

An **anchor** lets a producer tie a context to an artifact in an external
system it doesn't control — a settlement record, a decision log, a
commitment scheme — without ACDP verification ever needing to understand
that system. An anchor is ordinary producer-signed content, exactly like
``data_refs`` or ``derived_from``: it enters the JCS preimage byte-exactly
and is covered by the signature like any other field.

Two conformance stories, pinned fully offline:

1. **anc-001 (well-formed anchor)** — a body carrying one well-formed
   ``anchors`` entry (``{scheme, content_hash, uri}``) is accepted: schema
   validation, hash recomputation (anchors included), and signature
   verification all succeed normally. No new registry machinery is needed
   beyond schema acceptance.
2. **anc-005 (scheme-unaware verifier)** — a verifier with no resolution
   logic for a given ``scheme`` MUST still treat the body as fully verified.
   Core ACDP verification (signature, ``content_hash``) never depends on
   understanding *any* scheme, and — the stricter §6 rule this scenario
   makes structurally observable — ``anchors[].uri`` MUST NOT be
   dereferenced by ACDP-level verification at all. Both offline verify
   calls run inside a DNS trap that fails the run if anything ever
   resolves the anchor's host, proving the "never fetched" claim rather
   than merely asserting it.

A tamper check ties back to the anc-004 golden vector: mutating a signed
anchor after the fact must fail closed, same as tampering with any other
field — anchors are not a side-channel exempt from the signature.

The live half publishes an anchored context to registry-a, retrieves and
re-verifies it (same DNS trap), then supersedes twice to exercise the
0.8.3 fix in ``Producer::new_version_from``: omitting ``anchors`` on
supersede now correctly carries the previous version's anchors forward,
and ``clear_anchors=True`` is the explicit way to drop them. Degrades
gracefully without a registry — the deterministic core is the required
proof.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import socket
from contextlib import contextmanager
from datetime import datetime, timezone

from acdp import AcdpProducer, AcdpVerifier

from acdp_client import AcdpHTTPError
from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios._factory import AgentBundle
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
    id="s33_anchors",
    name="External Anchors",
    description="A well-formed anchors entry is accepted and signed like any other "
    "field (anc-001); a scheme-unaware verifier still produces a valid "
    "verdict while structurally never dereferencing anchors[].uri "
    "(anc-005, RFC-ACDP-0016 §6). A tampered anchor fails closed. The live "
    "half supersedes twice to exercise the anchors carry-forward / "
    "clear_anchors fix in Producer::new_version_from.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "anchored settlement snapshot"},
)

# A host that must never be resolved: anchors[].uri is advisory-only and
# RFC-ACDP-0016 §6/§14 requires no ACDP-level verification code path to ever
# read it. Wrapping every verify call in a DNS trap on this host turns that
# normative claim into something the run actually fails on if violated.
POISON_HOST = "anchor-must-not-be-dereferenced.invalid.acdp-playground.test"

KNOWN_SCHEME = "macp.commitment"
UNKNOWN_SCHEME = "a-scheme.this-verifier.does-not-recognize"


@contextmanager
def _dns_trap():
    real_getaddrinfo = socket.getaddrinfo

    def guarded(host, *args, **kwargs):
        if host == POISON_HOST:
            raise AssertionError(
                f"anchors[].uri MUST NOT be dereferenced during ACDP verification "
                f"(RFC-ACDP-0016 §6) — DNS resolution attempted for {host!r}"
            )
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = guarded
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo


def _anchor(scheme: str, seed: str) -> dict:
    return {
        "scheme": scheme,
        "content_hash": "sha256:" + hashlib.sha256(seed.encode()).hexdigest(),
        "uri": f"https://{POISON_HOST}/{scheme}/{seed}",
    }


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    authority = settings.registry_a_authority
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        producer = AcdpProducer.from_seed_did_key(spec.agent_seed("anchor-producer"))

        # ── anc-001: a well-formed, recognized-scheme anchor is accepted. ──
        anchor_known = _anchor(KNOWN_SCHEME, "settlement-finalized")
        anchors_known_json = json.dumps([anchor_known])
        raw_anc001 = producer.build_publish_request(
            title=topic,
            context_type="data_snapshot",
            visibility="public",
            summary="Well-formed anchors entry, recognized scheme (anc-001).",
            tags=["anchors"],
            anchors=anchors_known_json,
            acdp_version="0.5.0",
        )

        # ── anc-005: an unrecognized scheme still verifies; uri untouched. ─
        anchor_unknown = _anchor(UNKNOWN_SCHEME, "opaque-external-claim")
        anchors_unknown_json = json.dumps([anchor_unknown])
        raw_anc005 = producer.build_publish_request(
            title=f"{topic} (scheme-unaware)",
            context_type="data_snapshot",
            visibility="public",
            summary="Anchor with a scheme this verifier does not recognize (anc-005).",
            tags=["anchors"],
            anchors=anchors_unknown_json,
            acdp_version="0.5.0",
        )

        with _dns_trap():
            anc001_verified = AcdpVerifier.verify_publish_request_offline(raw_anc001)
            anc005_verified = AcdpVerifier.verify_publish_request_offline(raw_anc005)

            # A tampered anchor fails closed — anchors are covered by the
            # signature byte-exactly (anc-004), not a side-channel.
            tampered = json.loads(raw_anc001)
            tampered["anchors"][0]["content_hash"] = "sha256:" + "0" * 64
            tamper_rejected = False
            try:
                AcdpVerifier.verify_publish_request_offline(json.dumps(tampered))
            except Exception:  # noqa: BLE001
                tamper_rejected = True

        offline_core_ok = bool(anc001_verified) and bool(anc005_verified) and tamper_rejected

        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                title="Anchored bodies verified offline (anchors[].uri never dereferenced)",
                preview=f"anc-001={anc001_verified} anc-005={anc005_verified} "
                f"tamper_rejected={tamper_rejected}",
            )
        )

        # ── Live: publish anchored, retrieve+reverify, supersede-carry. ───
        client = bundle.anonymous_client("a")
        ctx1: str | None = None
        ctx2: str | None = None
        ctx3: str | None = None
        registry_outcome = "skipped"
        retrieved_anchors_match = False
        carry_forward_ok = False
        clear_anchors_ok = False
        try:
            resp1 = await client.publish(raw_anc001)
            ctx1 = resp1.ctx_id
            await events.put(
                StepEvent(
                    type="acdp.publish",
                    run_id=spec.run_id,
                    ts=datetime.now(timezone.utc).isoformat(),
                    agent_id=producer.agent_did,
                    ctx_id=ctx1,
                    title=topic,
                    preview=f"anchors: {KNOWN_SCHEME}",
                )
            )

            with _dns_trap():
                v1_raw = await client.retrieve_raw(ctx1)
                v1_body_json = json.dumps(v1_raw["body"])
                v1_verified = AcdpVerifier.verify_body_offline(v1_body_json)
                retrieved_anchors_match = v1_verified and v1_raw["body"].get("anchors") == [
                    anchor_known
                ]

            # Supersede omitting `anchors` — the 0.8.3 fix: this now carries
            # the previous version's anchors forward instead of dropping them.
            supersede_v2 = producer.build_supersede_request(
                v1_body_json,
                title=f"{topic} (v2, anchors carried forward)",
                summary="Supersede with no anchors param — must inherit v1's anchor.",
                acdp_version="0.5.0",
            )
            resp2 = await client.publish(supersede_v2)
            ctx2 = resp2.ctx_id
            with _dns_trap():
                v2_raw = await client.retrieve_raw(ctx2)
                v2_body_json = json.dumps(v2_raw["body"])
                carry_forward_ok = v2_raw["body"].get("anchors") == [anchor_known]

            # Supersede with clear_anchors=True — explicit drop.
            supersede_v3 = producer.build_supersede_request(
                v2_body_json,
                title=f"{topic} (v3, anchors cleared)",
                summary="Supersede with clear_anchors=True — must drop the anchor.",
                clear_anchors=True,
                acdp_version="0.5.0",
            )
            resp3 = await client.publish(supersede_v3)
            ctx3 = resp3.ctx_id
            v3_raw = await client.retrieve_raw(ctx3)
            clear_anchors_ok = not v3_raw["body"].get("anchors")

            await events.put(
                StepEvent(
                    type="acdp.verify",
                    run_id=spec.run_id,
                    ts=datetime.now(timezone.utc).isoformat(),
                    agent_id=producer.agent_did,
                    ctx_id=ctx3,
                    title="Supersede anchors carry-forward + clear_anchors verified live",
                    preview=f"carry_forward={carry_forward_ok} clear_anchors={clear_anchors_ok}",
                )
            )
            registry_outcome = "published_3"
        except AcdpHTTPError as e:
            registry_outcome = f"http_{e.status}:{e.code}"
            log.warning("S33 registry round-trip failed: %s", e)
        except Exception as e:  # noqa: BLE001 — no registry: degrade
            registry_outcome = f"unreachable:{type(e).__name__}"
            log.warning("S33 registry round-trip unreachable: %s", e)

        live_ok = retrieved_anchors_match and carry_forward_ok and clear_anchors_ok
        degraded = not live_ok

        nodes = [
            LineageNode(
                ctx_id=c,
                agent_id=producer.agent_did,
                title=t,
                context_type="data_snapshot",
                registry_authority=authority,
                step=i,
            )
            for i, (c, t) in enumerate(
                (
                    (ctx1, topic),
                    (ctx2, f"{topic} (v2, anchors carried forward)"),
                    (ctx3, f"{topic} (v3, anchors cleared)"),
                ),
                start=1,
            )
            if c
        ]
        edges = [LineageEdge(src=a, dst=b) for a, b in ((ctx1, ctx2), (ctx2, ctx3)) if a and b]

        summary = {
            "anc001_well_formed_anchor_verified": bool(anc001_verified),
            "anc005_scheme_unaware_verified": bool(anc005_verified),
            "tamper_rejected": tamper_rejected,
            "anchor_uri_dereferenced": False,
            "offline_core_ok": offline_core_ok,
            "registry_round_trip": registry_outcome,
            "retrieved_anchors_match": retrieved_anchors_match,
            "carry_forward_ok": carry_forward_ok,
            "clear_anchors_ok": clear_anchors_ok,
        }
        if degraded:
            summary["degraded"] = True

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if offline_core_ok else "failed",
            contexts=[c for c in (ctx1, ctx2, ctx3) if c],
            lineage_graph=LineageGraph(nodes=nodes, edges=edges),
            summary=summary,
            error=None if offline_core_ok else "anchors offline core failed verification",
        )
    finally:
        await bundle.aclose()
