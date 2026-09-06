"""S21 — P-256 capability self-declaration the control plane now accepts.

An agent self-declares a capability at the control plane via ``POST
/capabilities`` with a signature over
``acdp-cap:v1:<agent_did>:<capability_uri>:<declared_at>``. CP #51 fixed the
request DTO, whose ``@IsIn(['ed25519'])`` previously rejected a **P-256**-pinned
agent's declaration at the validation boundary (400) even though the service
verifies both Ed25519 and ECDSA P-256 — the DTO now accepts ``ecdsa-p256``.

This scenario is the *producer* side of that contract and is fully offline +
deterministic: it mints a P-256 agent, builds the canonical capability signing
string, signs it (``AcdpP256Producer.sign_challenge``), and asserts the emitted
declaration is the exact ``ecdsa-p256`` shape the fixed DTO accepts. It then
**re-verifies the signature locally** (``AcdpVerifier.verify_signature_p256``)
so the scenario proves the declaration is cryptographically valid, not merely
well-shaped — the same bytes the control plane checks against the agent's pinned
key. No network is required; the live ``POST`` is exercised in ``tests/live``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from acdp import AcdpVerifier

from acdp_client.models import StepEvent
from acdp_client.signing import producer_algorithm
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, did_for, key_id_for, producer_for
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

# CP #51 accepts these capability signature algorithms (was ed25519-only).
_CP_ACCEPTED_ALGS = {"ed25519", "ecdsa-p256"}

SCENARIO = ScenarioDef(
    id="s21_capabilities_p256",
    name="CP capability P-256 declaration",
    description="A P-256 agent self-declares a capability with the ecdsa-p256 "
    "signature the control plane's capability DTO now accepts (CP #51). "
    "Fully offline + deterministic; signature self-verified.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={},
)


def capability_signing_input(agent_did: str, capability_uri: str, declared_at: str) -> str:
    """The exact string the CP verifies a capability signature against."""
    return f"acdp-cap:v1:{agent_did}:{capability_uri}:{declared_at}"


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    authority = settings.registry_a_authority
    slug = "p256-cap-agent"
    capability_uri = "urn:acdp:cap:publish:data_snapshot:finance"

    async def note(title: str, preview: str) -> None:
        await events.put(
            StepEvent(
                type="scenario.note",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                title=title,
                preview=preview,
            )
        )

    try:
        producer = producer_for(spec, slug, authority, algorithm="ecdsa-p256")
        did = did_for(authority, slug)
        key_id = key_id_for(authority, slug)
        alg = producer_algorithm(producer)
        assert alg == "ecdsa-p256", f"expected ecdsa-p256 producer, got {alg}"

        declared_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        signing_input = capability_signing_input(did, capability_uri, declared_at)
        signature = producer.sign_challenge(signing_input)

        # The POST body the CP #51 DTO now accepts.
        declaration = {
            "agent_did": did,
            "capability_uri": capability_uri,
            "declared_at": declared_at,
            "key_id": key_id,
            "algorithm": alg,
            "signature": signature,
        }

        alg_ok = alg in _CP_ACCEPTED_ALGS
        shape_ok = (
            declaration["agent_did"] == did and declaration["key_id"] == key_id and bool(signature)
        )

        # Prove the signature is real — verify it against the producer's P-256
        # public key over the exact canonical string, the same check the CP runs
        # against the agent's pinned key.
        try:
            sig_ok = AcdpVerifier.verify_signature_p256(
                producer.public_key_sec1_b64, signature, signing_input
            )
        except Exception as e:  # noqa: BLE001 — a bad signature raises
            sig_ok = False
            log.warning("s21 capability signature self-verify failed: %s", e)

        conformant = alg_ok and shape_ok and sig_ok

        await note(
            "P-256 capability declaration",
            f"algorithm={alg} signed_ok={sig_ok} uri={capability_uri}",
        )
        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                agent_id=did,
                title="capability declaration is CP-acceptable (P-256, self-verified)",
                preview=f"conformant={conformant}",
            )
        )

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if conformant else "failed",
            contexts=[],
            summary={
                "algorithm": alg,
                "capability_uri": capability_uri,
                "signature_verified": sig_ok,
                "cp_acceptable": conformant,
                "declaration": declaration,
                "signing_input": signing_input,
            },
            error=None if conformant else "S21: P-256 capability declaration is not CP-acceptable",
        )
    finally:
        await bundle.aclose()
