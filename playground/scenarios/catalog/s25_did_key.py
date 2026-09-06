"""S25 — did:key ephemeral agents (RFC-ACDP-0001 §5.4, ACDP 0.2 workstream C).

Short-lived agents with no domain and no DID hosting: each identity is a
``did:key:z…`` that carries its Ed25519 public key *in the DID itself*. A
consumer verifies such a context **entirely offline** — no DID-document fetch,
no network, no SSRF surface — via ``AcdpVerifier.verify_body_offline`` /
``verify_publish_request_offline``.

Two things are pinned:

1. **Offline verification** — N deterministic ephemeral ``did:key`` agents each
   build and self-verify a publish request offline; a tampered body fails
   closed. This is the deterministic core (runs without any registry).
2. **Lineage-continuity tradeoff** — a ``did:key`` agent cannot "rotate": a new
   key *is* a new identity (a different ``did:key``), so the rotated agent
   cannot supersede the original's context. Offline we assert the identities
   differ; live we assert the registry rejects the cross-identity supersession
   (producer-continuity gate). This pins the documented did:key tradeoff.

The live publish targets registry-a, which advertises ``did:key`` in
``auth.did_methods``; it degrades gracefully when no registry is reachable.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

from acdp import AcdpProducer, AcdpVerifier

from acdp_client import AcdpHTTPError
from acdp_client.models import StepEvent
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s25_did_key",
    name="did:key Ephemeral Agents",
    description="Short-lived did:key agents publish with keys embedded in the "
    "DID; consumers verify entirely offline (no DID fetch). A "
    "rotated did:key is a new identity, so it cannot supersede — "
    "pinning the documented lineage-continuity tradeoff.",
    registry_mode="single",
    agent_count=3,
    framework="langchain",
    default_inputs={"agent_count": 3},
)


def _did_key_producer(spec: RunSpec, slug: str) -> AcdpProducer:
    """A deterministic ephemeral did:key producer for ``slug`` in this run."""
    return AcdpProducer.from_seed_did_key(spec.agent_seed(slug))


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    authority = settings.registry_a_authority
    n = int(spec.inputs.get("agent_count", SCENARIO.default_inputs["agent_count"]))

    try:
        client = bundle.anonymous_client("a")

        # ── Deterministic offline core: N ephemeral agents self-verify. ───
        offline_verified = 0
        requests: list[tuple[AcdpProducer, str]] = []
        for i in range(n):
            producer = _did_key_producer(spec, f"ephemeral-{i}")
            assert producer.agent_did.startswith("did:key:"), producer.agent_did
            raw = producer.build_publish_request(
                title=f"ephemeral snapshot {i}",
                context_type="data_snapshot",
                visibility="public",
                summary=f"Published by ephemeral did:key agent {i}.",
                tags=["did-key", "ephemeral"],
            )
            # Offline: no DID resolution — the key lives in the DID.
            if AcdpVerifier.verify_publish_request_offline(raw):
                offline_verified += 1
            requests.append((producer, raw))

        # Tamper fails closed offline.
        _, sample = requests[0]
        tampered = json.loads(sample)
        tampered["title"] = tampered["title"] + " (tampered)"
        tamper_rejected = False
        try:
            AcdpVerifier.verify_publish_request_offline(json.dumps(tampered))
        except Exception:  # noqa: BLE001
            tamper_rejected = True

        # Rotation = new identity: a fresh seed yields a different did:key.
        original = requests[0][0]
        rotated = _did_key_producer(spec, "ephemeral-0-rotated")
        identity_changed = original.agent_did != rotated.agent_did

        offline_core_ok = offline_verified == n and tamper_rejected and identity_changed

        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                agent_id=original.agent_did,
                title="did:key bodies verified offline",
                preview=f"{offline_verified}/{n} verified offline; "
                f"rotation_is_new_identity={identity_changed}",
            )
        )

        # ── Live: publish, retrieve+verify offline, supersession rejection.
        published: list[tuple[str, str]] = []  # (ctx_id, agent_did)
        registry_outcome = "skipped"
        retrieved_verified = 0
        supersede_rejected = False
        supersede_outcome = "skipped"
        try:
            for producer, raw in requests:
                resp = await client.publish(raw)
                published.append((resp.ctx_id, producer.agent_did))
                await events.put(
                    StepEvent(
                        type="acdp.publish",
                        run_id=spec.run_id,
                        ts=datetime.now(UTC).isoformat(),
                        agent_id=producer.agent_did,
                        ctx_id=resp.ctx_id,
                        title="ephemeral did:key publish",
                        preview="did:key",
                    )
                )

            # Retrieve each and verify the body fully offline.
            for ctx_id, _ in published:
                full = await client.retrieve_raw(ctx_id)
                if AcdpVerifier.verify_body_offline(json.dumps(full["body"])):
                    retrieved_verified += 1
            registry_outcome = f"published_{len(published)}"

            # Cross-identity supersession: the rotated did:key agent tries to
            # supersede the first context. The registry's producer-continuity
            # gate must reject it (new key = new identity, not the predecessor).
            if published:
                first_ctx, _ = published[0]
                prev_raw = await client.retrieve_raw(first_ctx)
                prev_body_json = json.dumps(prev_raw["body"])
                supersede_raw = rotated.build_supersede_request(
                    prev_body_json,
                    title="hostile supersession by a rotated identity",
                    summary="should be rejected: rotated did:key is not the original producer.",
                )
                try:
                    await client.publish(supersede_raw)
                    supersede_outcome = "accepted_cross_identity_supersede"
                    log.warning(
                        "S25: registry accepted a cross-identity "
                        "did:key supersession (continuity not enforced)"
                    )
                except AcdpHTTPError as e:
                    supersede_outcome = f"http_{e.status}:{e.code}"
                    # Any 4xx rejection is the spec'd outcome.
                    supersede_rejected = 400 <= e.status < 500
        except AcdpHTTPError as e:
            registry_outcome = f"http_{e.status}:{e.code}"
            log.warning("S25 publish failed: %s", e)
        except Exception as e:  # noqa: BLE001 — no registry: degrade
            registry_outcome = f"unreachable:{type(e).__name__}"
            log.warning("S25 registry round-trip unreachable: %s", e)

        live_ok = len(published) == n and retrieved_verified == n and supersede_rejected
        degraded = not live_ok

        nodes = [
            LineageNode(
                ctx_id=ctx_id,
                agent_id=agent_did,
                title=f"ephemeral snapshot {i}",
                context_type="data_snapshot",
                registry_authority=authority,
                step=i + 1,
            )
            for i, (ctx_id, agent_did) in enumerate(published)
        ]

        summary = {
            "agent_count": n,
            "offline_verified": offline_verified,
            "tamper_rejected": tamper_rejected,
            "rotation_is_new_identity": identity_changed,
            "offline_core_ok": offline_core_ok,
            "registry_round_trip": registry_outcome,
            "retrieved_verified_offline": retrieved_verified,
            "supersede_outcome": supersede_outcome,
            "supersede_rejected": supersede_rejected,
        }
        if degraded:
            summary["degraded"] = True

        # Offline self-verification + the rotation tradeoff is the contract;
        # the registry round-trip is the live extension.
        ok = offline_core_ok and supersede_outcome != "accepted_cross_identity_supersede"
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if ok else "failed",
            contexts=[c for c, _ in published],
            lineage_graph=LineageGraph(nodes=nodes, edges=[]),
            summary=summary,
            error=None
            if ok
            else "did:key offline core failed or registry accepted a cross-identity supersession",
        )
    finally:
        await bundle.aclose()
