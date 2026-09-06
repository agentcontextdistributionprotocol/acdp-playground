"""S19 — control-plane did:web P-256 conformance.

The control plane's did:web verification-method parser previously accepted
only ``Ed25519VerificationKey2020`` / ``JsonWebKey2020``, so a P-256 agent the
registry happily authenticates was *silently rejected* at the CP. CP #49
restores parity: it now resolves ``EcdsaSecp256r1VerificationKey2019``,
``Multikey``, and ``JsonWebKey2020`` and — like the acdp-rs consumer — keeps
P-256 key bytes **JWK-only** so it never accepts a document the registry
would reject.

This scenario is the *producer* side of that contract, and is fully offline +
deterministic: it mints a P-256 agent, emits the did:web verification method
the SDK produces (``AcdpP256Producer.did_verification_method``), and asserts it
is exactly the JWK-only ``JsonWebKey2020`` shape (``kty=EC`` / ``crv=P-256``)
the fixed CP resolver accepts — i.e. the playground publishes a DID document
the control plane can now consume. It assembles the ``did.json`` the CP would
fetch from ``/.well-known/`` and then **resolves it through the same Rust
did:web consumer gate the CP uses** (``acdp.AcdpDidDocument``, acdp-py 0.3.0),
asserting the recovered key is the producer's signing key — so the scenario
proves the document is resolvable, not merely well-shaped. No network is
required; when the full stack is up the same document is what the CP resolves.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

from acdp_client import AcdpDidDocument, DidResolutionError
from acdp_client.models import StepEvent
from acdp_client.signing import producer_algorithm
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, did_for, key_id_for, producer_for
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s19_cp_did_web_p256",
    name="CP did:web P-256 conformance",
    description="The playground's P-256 agent emits the JWK-only JsonWebKey2020 "
    "verification method the control plane's did:web resolver now "
    "accepts (CP #49). Fully offline + deterministic.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={},
)

# The CP #49 resolver accepts these verification-method types; P-256 key
# bytes are JWK-only (no raw multibase), matching the acdp-rs consumer.
_CP_ACCEPTED_VM_TYPES = {
    "Ed25519VerificationKey2018",
    "Ed25519VerificationKey2020",
    "EcdsaSecp256r1VerificationKey2019",
    "JsonWebKey2020",
    "Multikey",
}


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    authority = settings.registry_a_authority
    slug = "p256-did-agent"

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

        # The verification method the SDK emits — what the CP resolver consumes.
        vm = json.loads(producer.did_verification_method(key_id, did))
        jwk = vm.get("publicKeyJwk", {})

        type_ok = vm.get("type") in _CP_ACCEPTED_VM_TYPES
        jwk_only = "publicKeyJwk" in vm and "publicKeyMultibase" not in vm
        jwk_p256 = jwk.get("kty") == "EC" and jwk.get("crv") == "P-256"
        id_ok = vm.get("id") == key_id and vm.get("controller") == did
        conformant = type_ok and jwk_only and jwk_p256 and id_ok

        # The did:web document the CP would fetch from /.well-known/did.json.
        did_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
            ],
            "id": did,
            "verificationMethod": [vm],
            "assertionMethod": [key_id],
            "authentication": [key_id],
        }

        # Prove the emitted document is not merely *shaped* right but actually
        # *resolvable*: run it through the same Rust did:web consumer gate the CP
        # uses (acdp-py 0.3.0 — assertionMethod authorization + algorithm-downgrade
        # defense) and assert the recovered key is the producer's signing key.
        resolvable = False
        resolve_detail = ""
        try:
            doc = AcdpDidDocument.parse(json.dumps(did_document), did)
            resolved = doc.key_for_algorithm(key_id, "ecdsa-p256")
            resolvable = resolved["public_key_b64"] == producer.public_key_sec1_b64
            resolve_detail = "key matches producer" if resolvable else "key mismatch"
        except DidResolutionError as e:
            resolve_detail = f"rejected: {getattr(e, 'reason', '?')}"

        conformant = conformant and resolvable

        await note(
            "P-256 verification method",
            f"type={vm.get('type')} jwk_only={jwk_only} crv={jwk.get('crv')}",
        )
        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                agent_id=did,
                title="did:web document is CP-resolvable (P-256, JWK-only)",
                preview=f"conformant={conformant} resolve={resolve_detail}",
            )
        )

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if conformant else "failed",
            contexts=[],
            summary={
                "algorithm": alg,
                "vm_type": vm.get("type"),
                "jwk_only": jwk_only,
                "jwk_curve": jwk.get("crv"),
                "cp_resolvable": conformant,
                "did_resolves": resolvable,
                "verification_method": vm,
                "did_document": did_document,
            },
            error=None if conformant else "S19: P-256 verification method is not CP-resolvable",
        )
    finally:
        await bundle.aclose()
