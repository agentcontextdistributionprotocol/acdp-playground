"""S28 — lifecycle events & retraction (RFC-ACDP-0013, ACDP 0.3.0).

Retraction is **mark-not-delete**: a producer formally withdraws a context
from reliance by POSTing a *signed lifecycle event* to
``/contexts/{id}/retract``; the body stays permanently retrievable,
byte-identical to what was signed — only the reliance signal
(``status: retracted``) changes. Republication reverses it; both events stay
in the append-only ``registry_state.lifecycle_events`` history.

Deterministic core (offline). A did:key producer mints lifecycle events with
the RFC-ACDP-0013 §5 construction (the RFC-ACDP-0010 §5 preimage verbatim:
JCS minus ``signature``, SHA-256, signature over the ASCII ``"sha256:<hex>"``
string) and the consumer verifies them with
:meth:`AcdpVerifier.verify_lifecycle_event`:

* a well-formed signed retraction verifies (did:key actor — no DID doc);
* the ctx_id **replay binding** holds: the same signed event presented
  against another context is rejected;
* any tamper (``reason`` edit) and a missing signature fail closed;
* the §7.1 derivation is order-based, **last** ``retracted``/``republished``
  event wins — unknown event types are inert;
* the §4/§12 authorization rule the host owns: ``actor`` must equal the
  context's ``body.agent_id``.

The live half drives registry-c (lifecycle-profile): publish v1 → supersede
v2 → **retract v2** (status ``retracted``, body still retrievable, default
search excludes it, ``/current`` 404s because v1 is superseded — RFC-ACDP-0013
§8.3 leaves no eligible head), a double retract is refused
``invalid_lifecycle_transition`` (409), then **republish** → active again and
``/current`` serves v2 once more. Every served lifecycle event is re-verified
with the SDK. Degrades gracefully without a registry.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from acdp import AcdpProducer, AcdpVerifier

from acdp_client import (
    AcdpClient,
    AcdpHTTPError,
    InvalidLifecycleTransitionError,
)
from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios._receipts import mint_lifecycle_event
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
    id="s28_lifecycle_retraction",
    name="Lifecycle Events & Retraction",
    description="A producer retracts a context with a signed lifecycle event "
    "(mark-not-delete): status flips to retracted while the body stays "
    "retrievable, default search excludes it, /current applies the §8.3 "
    "head exclusion, a double retract is refused "
    "invalid_lifecycle_transition, and a republish reverses it. Every "
    "event verifies offline via verify_lifecycle_event.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "flash sales estimate"},
)


def _now_ms() -> str:
    """Canonical millisecond-precision RFC 3339 UTC (RFC-ACDP-0001 §5.3)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _verify_event(event: dict, ctx_id: str) -> dict:
    """SDK verification of one lifecycle event (did:key actor → no DID doc)."""
    return json.loads(AcdpVerifier.verify_lifecycle_event(json.dumps(event), None, ctx_id))


def _retraction_state(events: list[dict]) -> bool:
    """RFC-ACDP-0013 §7.1: the LAST retracted/republished event in array
    order decides; unknown event types are inert. (Display-side mirror of
    the registry's derivation — the registry's ``status`` stays the
    authoritative wire signal.)"""
    for event in reversed(events):
        if event.get("event_type") == "retracted":
            return True
        if event.get("event_type") == "republished":
            return False
    return False


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_c_authority
    title = f"{topic} — retractable"

    producer = AcdpProducer.from_seed_did_key(spec.agent_seed("lifecycle-producer"))

    # ── Deterministic offline core: mint + verify lifecycle events. ──────
    offline_ctx = f"acdp://{authority}/00000028-cccc-4ccc-8ccc-cccccccccccc"

    def _mint(event_type: str, reason: str | None = None) -> dict:
        return mint_lifecycle_event(
            producer,
            event_id=str(uuid.uuid4()),
            ctx_id=offline_ctx,
            event_type=event_type,
            occurred_at=_now_ms(),
            reason=reason,
        )

    retract_event = _mint("retracted", "underlying data source found to be fabricated")
    republish_event = _mint("republished", "source re-validated")

    # (a) A well-formed signed retraction verifies (did:key — no DID doc).
    event_verified = _verify_event(retract_event, offline_ctx).get("valid") is True

    # (b) Replay binding: the SAME signed event against another ctx_id fails.
    other_ctx = f"acdp://{authority}/00000028-dddd-4ddd-8ddd-dddddddddddd"
    replay_rejected = _verify_event(retract_event, other_ctx).get("valid") is False

    # (c) Tampered reason breaks the signature; an unsigned event fails closed
    #     (producer-initiated events MUST be signed, §5).
    tampered = dict(retract_event, reason="innocuous edit")
    tamper_rejected = _verify_event(tampered, offline_ctx).get("valid") is False
    unsigned = {k: v for k, v in retract_event.items() if k != "signature"}
    unsigned_rejected = _verify_event(unsigned, offline_ctx).get("valid") is False

    # (d) §7.1 order-based derivation: last registered event wins; unknown
    #     event types are inert.
    annotated = dict(retract_event, event_type="annotated")  # unknown type
    derivation_ok = (
        _retraction_state([retract_event]) is True
        and _retraction_state([retract_event, republish_event]) is False
        and _retraction_state([retract_event, republish_event, retract_event]) is True
        and _retraction_state([retract_event, republish_event, annotated]) is False
    )

    # (e) The host-owned §4/§12 authorization rule: the actor must be the
    #     context's producer (body.agent_id) — a stranger's event, even
    #     validly signed by the stranger, must not be honored.
    stranger = AcdpProducer.from_seed_did_key(spec.agent_seed("lifecycle-stranger"))
    stranger_event = mint_lifecycle_event(
        stranger,
        event_id=str(uuid.uuid4()),
        ctx_id=offline_ctx,
        event_type="retracted",
        occurred_at=_now_ms(),
    )
    stranger_verdict = _verify_event(stranger_event, offline_ctx)
    # The signature itself verifies (it IS the stranger's event)…
    # …but the host authorization check rejects it: actor != producer DID.
    authz_check_ok = (
        stranger_verdict.get("valid") is True
        and stranger_verdict.get("actor") == stranger.agent_did
        and stranger_verdict.get("actor") != producer.agent_did
    )

    offline_core_ok = (
        event_verified
        and replay_rejected
        and tamper_rejected
        and unsigned_rejected
        and derivation_ok
        and authz_check_ok
    )

    await events.put(
        StepEvent(
            type="acdp.verify",
            run_id=spec.run_id,
            ts=datetime.now(timezone.utc).isoformat(),
            agent_id=producer.agent_did,
            title="Lifecycle event construction verified",
            preview=f"signed={event_verified} replay_rejected={replay_rejected} "
            f"tamper_rejected={tamper_rejected} derivation_ok={derivation_ok}",
        )
    )

    # ── Live: publish v1 → v2, retract v2, observe, republish. ───────────
    client = AcdpClient(settings.registry_c_url, run_id=spec.run_id)
    ctx_v1: str | None = None
    ctx_v2: str | None = None
    live_round_trip = "skipped"
    retracted_status_ok = False
    body_still_retrievable = False
    served_events_verified = False
    search_excludes_retracted = False
    current_head_excluded = False
    double_retract_conflict = False
    republished_active_ok = False
    current_restored = False
    try:
        raw_v1 = producer.build_publish_request(
            title=title,
            context_type="data_snapshot",
            visibility="public",
            summary="v1 — will be superseded.",
            domain="finance",
            tags=["lifecycle", "retraction"],
        )
        resp_v1 = await client.publish(raw_v1)
        ctx_v1 = resp_v1.ctx_id
        lineage_id = resp_v1.lineage_id
        await events.put(
            StepEvent(
                type="acdp.publish",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx_v1,
                title=f"{title} (v1)",
                preview="did:key → lifecycle registry",
            )
        )

        prev_body = json.dumps((await client.retrieve_raw(ctx_v1))["body"])
        raw_v2 = producer.build_supersede_request(
            prev_body,
            summary="v2 — corrected figures; will be retracted.",
            expected_lineage_id=lineage_id,
        )
        resp_v2 = await client.publish(raw_v2)
        ctx_v2 = resp_v2.ctx_id
        await events.put(
            StepEvent(
                type="acdp.publish",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx_v2,
                title=f"{title} (v2)",
                derived_from=[ctx_v1],
                preview="supersedes v1",
            )
        )

        # Retract v2 with a producer-signed event.
        live_retract = mint_lifecycle_event(
            producer,
            event_id=str(uuid.uuid4()),
            ctx_id=ctx_v2,
            event_type="retracted",
            occurred_at=_now_ms(),
            reason="figures withdrawn pending re-audit",
        )
        after_retract = await client.retract(ctx_v2, json.dumps(live_retract))
        retracted_status_ok = (
            after_retract.registry_state.status == "retracted" and after_retract.is_retracted
        )
        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx_v2,
                title="Context retracted",
                preview=f"status={after_retract.registry_state.status}",
            )
        )

        # Mark-not-delete: the body stays retrievable, byte-identical.
        full = await client.retrieve_raw(ctx_v2)
        body_still_retrievable = (
            full["body"]["content_hash"] == json.loads(raw_v2)["body"]["content_hash"]
            and full["registry_state"]["status"] == "retracted"
        )
        served = full["registry_state"].get("lifecycle_events") or []
        served_events_verified = bool(served) and all(
            _verify_event(e, ctx_v2).get("valid") is True
            and e.get("actor") == full["body"]["agent_id"]
            for e in served
        )

        # Default search excludes retracted contexts (§8.2).
        hits = await client.search(agent_id=producer.agent_did, limit=50)
        search_excludes_retracted = all(h.ctx_id != ctx_v2 for h in hits.matches)

        # §8.3 /current head exclusion: v2 retracted + v1 superseded leaves
        # no eligible head → 404 not_found.
        try:
            await client.current(lineage_id)
        except AcdpHTTPError as e:
            current_head_excluded = e.status == 404
        # A second retract conflicts with the current state (409).
        second_retract = mint_lifecycle_event(
            producer,
            event_id=str(uuid.uuid4()),
            ctx_id=ctx_v2,
            event_type="retracted",
            occurred_at=_now_ms(),
        )
        try:
            await client.retract(ctx_v2, json.dumps(second_retract))
        except InvalidLifecycleTransitionError as e:
            double_retract_conflict = e.status == 409

        # Republish: reliance restored, both events stay in the history.
        live_republish = mint_lifecycle_event(
            producer,
            event_id=str(uuid.uuid4()),
            ctx_id=ctx_v2,
            event_type="republished",
            occurred_at=_now_ms(),
            reason="re-audit complete",
        )
        after_republish = await client.republish(ctx_v2, json.dumps(live_republish))
        history = after_republish.registry_state.lifecycle_events or []
        republished_active_ok = (
            after_republish.registry_state.status == "active"
            and not after_republish.is_retracted
            and len(history) >= 2
            and not _retraction_state(history)
        )
        restored = await client.current(lineage_id)
        current_restored = restored.body.ctx_id == ctx_v2
        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=ctx_v2,
                title="Context republished",
                preview=f"status={after_republish.registry_state.status} events={len(history)}",
            )
        )
        live_round_trip = "verified"
    except AcdpHTTPError as e:
        live_round_trip = f"http_{e.status}:{e.code}"
        log.warning("S28 registry round-trip failed: %s", e)
    except Exception as e:  # noqa: BLE001 — no registry: degrade
        live_round_trip = f"unreachable:{type(e).__name__}"
        log.warning("S28 registry round-trip unreachable: %s", e)
    finally:
        await client.aclose()

    live_ok = (
        retracted_status_ok
        and body_still_retrievable
        and served_events_verified
        and search_excludes_retracted
        and current_head_excluded
        and double_retract_conflict
        and republished_active_ok
        and current_restored
    )
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
        "producer_did_method": "did:key",
        "event_verified": event_verified,
        "replay_rejected": replay_rejected,
        "tamper_rejected": tamper_rejected,
        "unsigned_rejected": unsigned_rejected,
        "derivation_ok": derivation_ok,
        "authz_check_ok": authz_check_ok,
        "offline_core_ok": offline_core_ok,
        "live_round_trip": live_round_trip,
        "retracted_status_ok": retracted_status_ok,
        "body_still_retrievable": body_still_retrievable,
        "served_events_verified": served_events_verified,
        "search_excludes_retracted": search_excludes_retracted,
        "current_head_excluded": current_head_excluded,
        "double_retract_conflict": double_retract_conflict,
        "republished_active_ok": republished_active_ok,
        "current_restored": current_restored,
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
        error=None if offline_core_ok else "lifecycle event core failed offline verification",
    )
