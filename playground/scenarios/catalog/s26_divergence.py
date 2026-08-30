"""S26 — sharp-edge divergence diagnostics.

A deliberately *buggy* producer is the point of this scenario: it bypasses
the SDK builder's guarantees and emits bodies whose ``content_hash`` won't
reproduce against a well-behaved counterparty. The ACDP 0.2 diagnostic API
(``AcdpVerifier.explain_hash_mismatch`` / ``canonical_preimage``) is exercised
to *name the cause* rather than leaving two opaque digests to stare at.

Two divergence classes are demonstrated, both deterministically offline:

1. **acdp_version form** — the SDK emits ``acdp_version`` explicitly since
   0.2; the 0.1.x omitted form is a *different* JCS preimage and hashes
   differently. ``explain_hash_mismatch`` auto-detects this and says so.
2. **field-level divergence** (a sub-millisecond ``expires_at``, RFC-ACDP-0001
   §5.3) — no canned pattern reproduces it, so the explainer falls back to
   dumping the exact canonical preimage; diffing it against the counterparty's
   ``canonical_preimage()`` localizes the offending bytes.

The live half publishes a tampered body (body mutated after the hash was
fixed) and asserts the registry rejects it with ``hash_mismatch``; it degrades
gracefully when no registry is reachable. The diagnostic core stands either
way.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from acdp import AcdpVerifier

from acdp_client import AcdpHTTPError
from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.scenarios.models import LineageGraph, RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s26_divergence",
    name="Divergence Diagnostics",
    description="A deliberately buggy producer emits non-reproducible content "
    "hashes (omitted acdp_version, sub-millisecond timestamps); the "
    "ACDP 0.2 explain_hash_mismatch / canonical_preimage API names "
    "the cause. Doubles as a registry hash_mismatch rejection demo.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "quarterly revenue model"},
)


def _body_of(request: dict) -> dict:
    """The hashable body view: the wire request minus its signature."""
    return {k: v for k, v in request.items() if k != "signature"}


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        agent = make_langchain_agent(
            spec,
            events,
            bundle,
            slug="buggy-producer",
            registry="a",
            method="did:key",
        )
        producer = agent.producer

        common = dict(
            title=f"{topic} — divergence probe",
            context_type="analysis",
            visibility="public",
            summary="content_hash reproduction across SDK versions.",
            domain="finance",
        )

        # ── Divergence 1: acdp_version omitted (0.1.x) vs explicit (0.2) ──
        # Pinned to 0.2.0 explicitly: explain_hash_mismatch's canned
        # divergence pattern for "omitted vs explicit acdp_version" is keyed
        # to the 0.1.x -> 0.2 transition specifically, not to whatever
        # acdp_version the SDK defaults to emitting today (which has moved
        # on as newer protocol surfaces landed).
        req_explicit = json.loads(producer.build_publish_request(**common, acdp_version="0.2.0"))
        req_omitted = json.loads(producer.build_publish_request(**common, omit_acdp_version=True))
        hash_explicit = req_explicit["content_hash"]
        hash_omitted = req_omitted["content_hash"]
        version_hashes_differ = hash_explicit != hash_omitted

        # Ask the diagnostic API why the omitted-form body doesn't reproduce
        # the explicit-form hash. It must name acdp_version as the cause.
        version_explanation = AcdpVerifier.explain_hash_mismatch(
            json.dumps(_body_of(req_omitted)), hash_explicit
        )
        version_cause_identified = "acdp_version" in version_explanation

        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=agent.agent_did,
                title="acdp_version divergence diagnosed",
                preview=version_explanation.splitlines()[-1][:160],
            )
        )

        # ── Divergence 2: sub-millisecond expires_at (RFC §5.3) ──────────
        # Build a clean body with a millisecond expires_at, then a buggy
        # producer hand-mutates it to microsecond precision while keeping the
        # original (now-stale) content_hash. The explainer can't reproduce it
        # from a canned pattern, so it surfaces the canonical preimage for a
        # byte-level diff that pinpoints expires_at.
        req_ttl = json.loads(
            producer.build_publish_request(**common, expires_at="2026-12-31T23:59:59.000Z")
        )
        clean_hash = req_ttl["content_hash"]
        buggy_body = _body_of(req_ttl)
        buggy_body["expires_at"] = "2026-12-31T23:59:59.000123Z"  # micro

        ts_explanation = AcdpVerifier.explain_hash_mismatch(json.dumps(buggy_body), clean_hash)
        clean_preimage = AcdpVerifier.canonical_preimage(json.dumps(_body_of(req_ttl)))
        buggy_preimage = AcdpVerifier.canonical_preimage(json.dumps(buggy_body))
        preimage_diff_localized = (
            "mismatch" in ts_explanation
            and clean_preimage != buggy_preimage
            and "000123" in buggy_preimage
        )

        diagnostics_ok = (
            version_hashes_differ and version_cause_identified and preimage_diff_localized
        )

        # ── Live: registry must reject a tampered (hash_mismatch) body ───
        # Take a validly-signed request, mutate a hashed field but keep the
        # old content_hash + signature. A correct registry recomputes the
        # hash and rejects with `hash_mismatch` (HTTP 400, RFC-ACDP-0007 §5).
        tampered = dict(req_explicit)
        tampered["title"] = req_explicit["title"] + " (tampered post-hash)"
        registry_outcome = "skipped"
        rejected_as_expected = False
        try:
            await agent.client.publish(json.dumps(tampered))
            # A publish that *succeeds* means the registry failed to catch the
            # tamper — that's a real failure, not graceful degradation.
            registry_outcome = "accepted_tampered_body"
            log.warning("S26: registry accepted a tampered body (no hash check)")
        except AcdpHTTPError as e:
            registry_outcome = f"http_{e.status}:{e.code}"
            rejected_as_expected = e.status == 400 and e.code == "hash_mismatch"
        except Exception as e:  # noqa: BLE001 — no registry reachable: degrade
            registry_outcome = f"unreachable:{type(e).__name__}"
            log.warning("S26 registry round-trip unreachable: %s", e)

        # Graceful degradation: offline, the live check can't run, but the
        # deterministic diagnostic core is the scenario's real contract.
        degraded = registry_outcome.startswith("unreachable")
        # Hard-fail only if the registry was reachable AND mis-accepted the
        # tampered body, or if the offline diagnostics themselves broke.
        ok = diagnostics_ok and registry_outcome != "accepted_tampered_body"

        summary = {
            "version_hashes_differ": version_hashes_differ,
            "version_cause_identified": version_cause_identified,
            "preimage_diff_localized": preimage_diff_localized,
            "diagnostics_ok": diagnostics_ok,
            "registry_rejection": registry_outcome,
            "rejected_as_hash_mismatch": rejected_as_expected,
        }
        if degraded:
            summary["degraded"] = True

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if ok else "failed",
            contexts=[],
            lineage_graph=LineageGraph(nodes=[], edges=[]),
            summary=summary,
            error=None
            if ok
            else f"divergence diagnostics or hash-mismatch rejection failed ({registry_outcome})",
        )
    finally:
        await bundle.aclose()
