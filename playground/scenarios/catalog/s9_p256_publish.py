"""S9 — ECDSA-P256 publish.

One agent signs with ECDSA-P256 (``acdp.AcdpP256Producer``) instead of
Ed25519, publishes a public context, and we verify the wire signature
with the P-256 verifier (``AcdpVerifier.verify_signature_p256``).

This exercises the SDK feature-parity work (P-256 producer + verifier)
and the registry's acceptance of ``algorithm: "ecdsa-p256"``. The local
crypto verification is deterministic and runs with or without a live
registry; the publish + retrieve round-trip needs registry-a.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

from acdp_client import AcdpHTTPError
from acdp_client.models import StepEvent
from acdp_client.signing import producer_algorithm, public_key_material, verify_signature
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s9_p256_publish",
    name="ECDSA-P256 Publish",
    description="An agent signs with ECDSA-P256 instead of Ed25519, publishes a "
    "public context, and the P-256 wire signature is verified "
    "end-to-end. Proves the SDK P-256 producer/verifier parity.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "post-quantum signature migration"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority

    try:
        agent = make_langchain_agent(
            spec,
            events,
            bundle,
            slug="p256-signer",
            registry="a",
            algorithm="ecdsa-p256",
            method="did:key",
        )

        # Sanity: the producer really is the P-256 type.
        alg = producer_algorithm(agent.producer)
        assert alg == "ecdsa-p256", f"expected ecdsa-p256 producer, got {alg}"

        # Build the request and verify the signature locally BEFORE we
        # rely on any registry — this is the deterministic, offline core.
        raw = agent.producer.build_publish_request(
            title=f"{topic} — P-256 signed",
            context_type="analysis",
            visibility="public",
            summary="Signed with ECDSA-P256 per RFC-ACDP signature-algorithms.",
            domain="security",
            tags=["p256", "signatures"],
        )
        req = json.loads(raw)
        wire_alg = req["signature"]["algorithm"]
        body = {k: v for k, v in req.items() if k != "content_hash"}

        from acdp import AcdpVerifier

        AcdpVerifier.verify_content_hash(json.dumps(body), req["content_hash"])
        sig_ok = verify_signature(
            wire_alg,
            public_key_material(agent.producer),
            req["signature"]["value"],
            req["content_hash"],
        )
        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                agent_id=agent.agent_did,
                title="P-256 signature verified locally",
                preview=f"algorithm={wire_alg} verified={sig_ok}",
            )
        )

        crypto_ok = wire_alg == "ecdsa-p256" and sig_ok

        # Publish + retrieve round-trip against the live registry. Degrade
        # gracefully if it isn't reachable — the crypto proof still stands.
        ctx_id: str | None = None
        registry_outcome = "skipped"
        try:
            resp = await agent.client.publish(raw)
            ctx_id = resp.ctx_id
            await agent._emit(
                "acdp.publish",
                ctx_id=ctx_id,
                title=f"{topic} — P-256 signed",
                preview="ecdsa-p256",
            )
            # Re-verify the body the registry hands back.
            full = await agent.client.retrieve(ctx_id)
            returned_alg = full.body.signature.algorithm
            verify_signature(
                returned_alg,
                public_key_material(agent.producer),
                full.body.signature.value,
                full.body.content_hash,
            )
            registry_outcome = "verified"
        except AcdpHTTPError as e:
            registry_outcome = f"http_{e.status}"
            log.warning("S9 registry round-trip failed: %s", e)
        except Exception as e:  # noqa: BLE001 — degrade, don't abort
            registry_outcome = f"error:{type(e).__name__}"
            log.warning("S9 registry round-trip error: %s", e)

        nodes = []
        if ctx_id:
            nodes.append(
                LineageNode(
                    ctx_id=ctx_id,
                    agent_id=agent.agent_did,
                    title=f"{topic} — P-256 signed",
                    context_type="analysis",
                    registry_authority=authority,
                    step=1,
                )
            )

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if crypto_ok else "failed",
            contexts=[ctx_id] if ctx_id else [],
            lineage_graph=LineageGraph(nodes=nodes, edges=[]),
            summary={
                "algorithm": wire_alg,
                "local_signature_verified": sig_ok,
                "crypto_ok": crypto_ok,
                "registry_round_trip": registry_outcome,
                "public_key_jwk": json.loads(agent.producer.public_key_jwk),
            },
            error=None if crypto_ok else f"P-256 verification failed (alg={wire_alg})",
        )
    finally:
        await bundle.aclose()
