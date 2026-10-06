"""Live-stack scenario verification against a REAL LLM provider.

Every other file under ``tests/live/`` drives deterministic registry /
control-plane HTTP probes (:mod:`playground.conformance`) — no LLM call ever
happens. This file is different: it runs the **real** S1-S34 scenario catalog
through the playground's own HTTP API (``POST /runs``) against a genuinely
running ``make up-full`` stack, with ``LLM_PROVIDER`` pointed at a real
provider (openai/anthropic) — every agent turn is a real, billed chat
completion, not the deterministic mock. The offline/mocked suites
(``tests/test_scenarios_offline.py``, ``tests/test_scenarios_mocked_registry.py``,
``tests/test_scenarios_round2.py``/``round3.py``) already pin each scenario's
deterministic core; this file is the live-and-real counterpart that catches
what those can't: whether a real LLM's actual output still round-trips through
a real registry/control-plane with every protocol attribute intact.

For each scenario this file:

1. Starts the run through the playground's own API and waits for a terminal
   state (``run_scenario`` below) — never inspects internals, only the HTTP
   surface any external caller has.
2. Asserts the scenario's own self-reported ``summary`` — which, for most
   scenarios, is itself computed via the same ``AcdpVerifier``/``AcdpClient``
   calls a rigorous caller would make (see e.g. S22's receipt verification
   block) — every documented boolean/value, not just "did it complete".
3. For every ``ctx_id`` the run produced, independently re-fetches it through
   a *fresh* ``AcdpClient`` (never reusing anything the scenario built) and
   re-verifies content_hash, signature (for did:key producers, fully offline
   against the key embedded in the DID), and — where registry-a is expected
   to have minted one — the registry receipt, including the two RFC-ACDP-0010
   host-only obligations (serving-authority binding checked against the URL
   actually queried, and a body hash the harness itself recomputed rather
   than trusting the echoed field). See ``deep_verify``'s docstring for the
   one inherent scope limit (a black-box HTTP client cannot recover a
   producer's raw private key to re-derive its fingerprint from scratch).

Special cases (each documented at its own test):

* **S10** structurally cannot avoid ``degraded: true`` under a bare
  ``make up-full`` stack (its two tenant-bound agents are ``did:web``, and
  this stack hosts no DID documents for them) — asserted as the *expected*
  passing outcome, not a failure.
* **S23** never opens a real socket even when the stack is fully up (one case
  uses an in-process ``httpx.MockTransport`` against a fictitious host) — it
  is run and fully asserted for its own sake, but contributes zero signal
  about the live stack.
* **S24** reuses a fixed, non-run-scoped ``did:web`` identity pinned in
  ``config/registry-a.toml`` (``rotating-historical``) — safe to re-run (each
  run signs distinct content) but not idempotent: every run permanently adds
  one more context to registry-a under that identity.
* **S12/S14** touch fixed, non-run-scoped state too (S12's pinned-key window
  math is keyed to hard-coded timestamps in ``config/registry-a.toml``; S14
  ingests a fixed ``ctx_id`` on every run) — both are safe to re-run, neither
  publishes a real context through the normal path.

Costs real money every time it runs — see the module-level skip gate below.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

import httpx
import pytest
import pytest_asyncio
from acdp import AcdpVerifier

from acdp_client import AcdpClient
from acdp_client.identifiers import is_conformant_ctx_id
from playground.config import Settings

# tests/live/conftest.py already skips this whole package unless
# ACDP_LIVE_STACK is set. This file additionally spends real, billed LLM API
# calls on every scenario (at least one real chat completion each; several —
# S3, S4, S25 — are multi-agent chains) — `make test-live` alone must never
# silently bill an API key, so it needs its own explicit opt-in.
pytestmark = pytest.mark.skipif(
    not os.environ.get("ACDP_LIVE_REAL_LLM"),
    reason=(
        "drives real, billed LLM API calls — set ACDP_LIVE_REAL_LLM=1 "
        "(in addition to ACDP_LIVE_STACK=1, after `make up-full` with a real "
        "OPENAI_API_KEY/ANTHROPIC_API_KEY in .env) to run this file"
    ),
)

PLAYGROUND_URL = os.environ.get("PLAYGROUND_URL", "http://localhost:8000")
# Real multi-agent LLM chains (S3 has 4 agents, S4 has 3, S25 has 3 by
# default) can comfortably take over a minute end to end. Generous on
# purpose — this suite is meant to run deep and slow, not fast.
RUN_TIMEOUT_SECS = 240.0
POLL_INTERVAL_SECS = 2.0


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings()


@pytest_asyncio.fixture
async def http() -> httpx.AsyncClient:
    async with httpx.AsyncClient(timeout=30.0) as client:
        yield client


# ── Orchestration ───────────────────────────────────────────────────────────


async def run_scenario(
    http: httpx.AsyncClient, scenario_id: str, inputs: dict[str, Any] | None = None
) -> dict[str, Any]:
    """``POST /runs``, poll ``GET /runs/{id}`` to a terminal state, return the RunResult."""
    resp = await http.post(
        f"{PLAYGROUND_URL}/runs",
        json={"scenario_id": scenario_id, "inputs": inputs or {}},
    )
    resp.raise_for_status()
    run_id = resp.json()["run_id"]

    deadline = time.monotonic() + RUN_TIMEOUT_SECS
    while True:
        r = await http.get(f"{PLAYGROUND_URL}/runs/{run_id}")
        r.raise_for_status()
        body = r.json()
        if body["status"] != "running":
            result = body["result"]
            assert result is not None, f"{scenario_id}: terminal status with no result payload"
            return result
        if time.monotonic() > deadline:
            raise AssertionError(
                f"{scenario_id}: run {run_id} did not reach a terminal state "
                f"within {RUN_TIMEOUT_SECS}s"
            )
        await asyncio.sleep(POLL_INTERVAL_SECS)


# ── Common assertions ────────────────────────────────────────────────────────


def assert_run_complete(result: dict[str, Any]) -> dict[str, Any]:
    """Baseline RunResult contract every scenario in this file must satisfy.

    Every scenario here is written to report ``status: complete`` even when
    it is *demonstrating* a rejection (S6/S17/S23/S25/S26 among others) —
    "failed" means the scenario's own self-check found something wrong, not
    that a rejection scenario "failed" by rejecting. Returns the summary
    dict (``{}`` if absent) for the caller to assert on further.
    """
    sid = result["scenario_id"]
    assert result["status"] == "complete", (
        f"{sid}: status={result['status']} error={result['error']!r}"
    )
    assert result["error"] is None, f"{sid}: complete but error is set: {result['error']!r}"
    return result.get("summary") or {}


def assert_not_degraded(summary: dict[str, Any], scenario_id: str) -> None:
    assert summary.get("degraded") is not True, (
        f"{scenario_id}: unexpectedly degraded under the full live stack "
        f"(playground+registry-a+registry-b+control-plane): {summary}"
    )


def authority_of(ctx_id: str) -> str:
    return ctx_id.removeprefix("acdp://").split("/", 1)[0]


def assert_conformant_ctx(ctx_id: str, *, expected_authority: str) -> None:
    assert is_conformant_ctx_id(ctx_id), f"non-conformant ctx_id: {ctx_id}"
    assert authority_of(ctx_id) == expected_authority, (
        f"{ctx_id}: expected authority {expected_authority!r}, got {authority_of(ctx_id)!r}"
    )


async def deep_verify(
    registry_url: str,
    ctx_id: str,
    *,
    settings: Settings,
    expect_receipt: bool,
) -> dict[str, Any]:
    """Independently re-fetch and re-verify one published context.

    Never trusts the scenario's own ``summary``: retrieves through a FRESH
    ``AcdpClient`` (which enforces the RFC-ACDP-0006 §4.1 ctx_id binding on
    every retrieval automatically), recomputes ``content_hash`` itself, and
    — for a did:key producer — fully re-verifies the body offline against
    the key embedded in its own DID (``verify_body_offline``: no network, no
    trust in the registry's word for it). When a receipt is present it is
    independently re-verified too, against a hash WE recomputed and the
    ctx_id WE asked for, plus the two RFC-ACDP-0010 host-only obligations:
    the serving-authority binding (checked against the URL actually queried,
    never a field inside the response) and the origin binding.

    Scope limit, inherent to black-box HTTP verification: this harness only
    ever sees the wire body, never a producer's raw private key, so it
    cannot independently re-derive a did:web producer's key fingerprint from
    scratch the way an in-process scenario can. The receipt's claimed
    ``key_fingerprint`` is therefore checked for internal consistency rather
    than re-derived — the adversarial proof of authenticity for a did:key
    producer comes from ``verify_body_offline`` succeeding in this same
    call, since that call independently verifies the signature against the
    key embedded in the DID itself.
    """
    async with AcdpClient(registry_url) as client:
        full = await client.retrieve_raw(ctx_id)
    body = full["body"]
    body_json = json.dumps(body)

    assert AcdpVerifier.verify_content_hash(body_json, body["content_hash"]), (
        f"{ctx_id}: content_hash did not reproduce"
    )
    if body["agent_id"].startswith("did:key:"):
        assert AcdpVerifier.verify_body_offline(body_json), (
            f"{ctx_id}: did:key body failed offline hash+signature+binding verification"
        )

    receipt = full.get("registry_receipt")
    if expect_receipt:
        assert receipt is not None, f"{ctx_id}: expected a registry receipt, got none"
    if receipt is not None:
        registry_pub = settings.receipt_verification_public_key_b64()
        assert registry_pub, "receipt_signing_seed_b64 not provisioned in Settings"
        assert AcdpVerifier.verify_receipt(
            json.dumps(receipt),
            body_json,
            registry_pub,
            ctx_id,
            body["content_hash"],
            receipt.get("key_fingerprint"),
        ), f"{ctx_id}: registry receipt failed verification"
        authority = authority_of(ctx_id)
        assert receipt.get("registry_did") == f"did:web:{authority}", (
            f"{ctx_id}: receipt.registry_did not bound to the authority actually queried"
        )
        assert receipt.get("origin_registry") == body["origin_registry"], (
            f"{ctx_id}: receipt.origin_registry does not match the served body's"
        )

    return full


# ── S1-S9: core publish/derivation/versioning/crypto ────────────────────────


async def test_s1_single_publish(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s1_single_publish")
    summary = assert_run_complete(result)
    assert result["contexts"] == [summary["ctx_id"]]
    ctx_id = result["contexts"][0]
    assert_conformant_ctx(ctx_id, expected_authority=settings.registry_a_authority)
    assert summary["agent"].startswith("did:key:")
    nodes = result["lineage_graph"]["nodes"]
    assert len(nodes) == 1 and nodes[0]["ctx_id"] == ctx_id
    assert nodes[0]["context_type"] == "data_snapshot"
    await deep_verify(settings.registry_a_url, ctx_id, settings=settings, expect_receipt=True)


async def test_s2_producer_consumer(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s2_producer_consumer")
    assert_run_complete(result)
    assert len(result["contexts"]) == 2
    producer_ctx, consumer_ctx = result["contexts"]
    for ctx in result["contexts"]:
        assert_conformant_ctx(ctx, expected_authority=settings.registry_a_authority)
    edges = result["lineage_graph"]["edges"]
    assert edges == [{"src": producer_ctx, "dst": consumer_ctx}]
    await deep_verify(settings.registry_a_url, producer_ctx, settings=settings, expect_receipt=True)
    consumer_full = await deep_verify(
        settings.registry_a_url, consumer_ctx, settings=settings, expect_receipt=True
    )
    assert consumer_full["body"]["derived_from"] == [producer_ctx]


async def test_s3_fanout(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s3_fanout")
    assert_run_complete(result)
    facets = ["clinical-trial outcomes", "manufacturing capacity", "payer dynamics"]
    assert len(result["contexts"]) == 1 + len(facets)
    base_ctx, *derivative_ctxs = result["contexts"]
    for ctx in result["contexts"]:
        assert_conformant_ctx(ctx, expected_authority=settings.registry_a_authority)
    edges = result["lineage_graph"]["edges"]
    assert {(e["src"], e["dst"]) for e in edges} == {(base_ctx, d) for d in derivative_ctxs}
    await deep_verify(settings.registry_a_url, base_ctx, settings=settings, expect_receipt=True)
    for d in derivative_ctxs:
        full = await deep_verify(settings.registry_a_url, d, settings=settings, expect_receipt=True)
        assert full["body"]["derived_from"] == [base_ctx]


async def test_s4_chain(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s4_chain")
    assert_run_complete(result)
    assert len(result["contexts"]) == 3
    a, b, c = result["contexts"]
    for ctx in result["contexts"]:
        assert_conformant_ctx(ctx, expected_authority=settings.registry_a_authority)
    edges = result["lineage_graph"]["edges"]
    assert {(e["src"], e["dst"]) for e in edges} == {(a, b), (a, c), (b, c)}
    for ctx in result["contexts"]:
        await deep_verify(settings.registry_a_url, ctx, settings=settings, expect_receipt=True)
    c_full = await deep_verify(settings.registry_a_url, c, settings=settings, expect_receipt=True)
    assert set(c_full["body"]["derived_from"]) == {a, b}


async def test_s5_cross_registry(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s5_cross_registry")
    summary = assert_run_complete(result)
    assert summary["cross_registry_edge"] is True
    assert len(result["contexts"]) == 2
    ctx_a, ctx_b = result["contexts"]
    assert_conformant_ctx(ctx_a, expected_authority=settings.registry_a_authority)
    assert_conformant_ctx(ctx_b, expected_authority=settings.registry_b_authority)
    edges = result["lineage_graph"]["edges"]
    assert edges == [{"src": ctx_a, "dst": ctx_b}]
    await deep_verify(settings.registry_a_url, ctx_a, settings=settings, expect_receipt=True)
    # registry-b is a bare core+discovery registry — no [receipt] section.
    full_b = await deep_verify(
        settings.registry_b_url, ctx_b, settings=settings, expect_receipt=False
    )
    assert full_b["body"]["derived_from"] == [ctx_a], (
        "cross-registry derivation edge must survive even though the edge spans authorities"
    )


async def test_s6_restricted(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s6_restricted")
    summary = assert_run_complete(result)
    assert summary["all_assertions_passed"] is True
    outcomes = summary["outcomes"]
    assert outcomes["anonymous"]["outcome"] == "denied"
    assert outcomes["outsider"]["outcome"] == "denied"
    assert outcomes["audience_member"]["outcome"] == "allowed"
    assert summary["audience"] == [summary["audience"][0]]
    assert summary["outsider_did"].startswith("did:key:")
    assert len(result["contexts"]) == 1
    ctx_id = result["contexts"][0]
    assert_conformant_ctx(ctx_id, expected_authority=settings.registry_a_authority)
    # Deliberately NOT independently re-fetched here: an anonymous
    # AcdpClient.retrieve is exactly the "denied" case this scenario itself
    # already exercises and asserts (outcomes["anonymous"]), and this harness
    # has no way to mint the audience member's own bearer token — re-driving
    # that path would only duplicate the scenario's own already-verified
    # three-way outcome, not add independent signal.
    nodes = result["lineage_graph"]["nodes"]
    assert len(nodes) == 1 and nodes[0]["ctx_id"] == ctx_id
    assert nodes[0]["context_type"] == "analysis"


async def test_s7_supersession(http: httpx.AsyncClient, settings: Settings) -> None:
    """v1 then v2 via the real supersede path (``agent.supersede()`` /
    ``build_supersede_request``). Lineage returns both; current returns v2.
    """
    result = await run_scenario(http, "s7_supersession")
    summary = assert_run_complete(result)
    assert summary["same_lineage"] is True
    assert summary["lineage_length"] == 2
    assert len(result["contexts"]) == 2
    v1, v2 = result["contexts"]
    for ctx in result["contexts"]:
        assert_conformant_ctx(ctx, expected_authority=settings.registry_a_authority)
    v1_full = await deep_verify(settings.registry_a_url, v1, settings=settings, expect_receipt=True)
    v2_full = await deep_verify(settings.registry_a_url, v2, settings=settings, expect_receipt=True)

    assert v1_full["body"]["version"] == 1
    assert v1_full["body"]["supersedes"] is None
    assert v2_full["body"]["version"] == 2
    assert v2_full["body"]["supersedes"] == v1
    assert v2_full["body"]["lineage_id"] == v1_full["body"]["lineage_id"]

    # Independent re-check of the registry's real /current answer — not just
    # trusting the scenario's own self-reported current_ctx_id.
    assert summary["current_ctx_id"] == v2
    async with AcdpClient(settings.registry_a_url) as client:
        current = await client.current(v1_full["body"]["lineage_id"])
        assert current.body.ctx_id == v2
        lineage = await client.lineage(v1_full["body"]["lineage_id"])
        assert {c.body.ctx_id for c in lineage} == {v1, v2}


async def test_s8_cross_org(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s8_cross_org")
    summary = assert_run_complete(result)
    assert summary["isolated_orgs"] is True
    assert result["lineage_graph"]["edges"] == []
    assert len(result["contexts"]) == 2
    ctx_a, ctx_b = result["contexts"]
    assert_conformant_ctx(ctx_a, expected_authority=settings.registry_a_authority)
    assert_conformant_ctx(ctx_b, expected_authority=settings.registry_b_authority)
    full_a = await deep_verify(
        settings.registry_a_url, ctx_a, settings=settings, expect_receipt=True
    )
    full_b = await deep_verify(
        settings.registry_b_url, ctx_b, settings=settings, expect_receipt=False
    )
    assert full_a["body"]["derived_from"] == []
    assert full_b["body"]["derived_from"] == []


async def test_s9_p256_publish(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s9_p256_publish")
    summary = assert_run_complete(result)
    assert summary["algorithm"] == "ecdsa-p256"
    assert summary["local_signature_verified"] is True
    assert summary["crypto_ok"] is True
    assert summary["registry_round_trip"] == "verified", (
        f"S9 live round-trip did not verify: {summary['registry_round_trip']}"
    )
    assert len(result["contexts"]) == 1
    ctx_id = result["contexts"][0]
    assert_conformant_ctx(ctx_id, expected_authority=settings.registry_a_authority)
    full = await deep_verify(
        settings.registry_a_url, ctx_id, settings=settings, expect_receipt=True
    )
    assert full["body"]["signature"]["algorithm"] == "ecdsa-p256"


# ── S10-S21: auth, tenancy, control-plane, lineage edge cases ───────────────


async def test_s10_tenant_isolation(http: httpx.AsyncClient, settings: Settings) -> None:
    """Structurally always degraded under a bare `make up-full` (see module docstring)."""
    result = await run_scenario(http, "s10_tenant_isolation")
    summary = assert_run_complete(result)
    assert summary["degraded"] is True, (
        "S10 unexpectedly NOT degraded — this stack has no DID-document hosting "
        "for the scenario's did:web tenant agents, so real live token issuance "
        "for them should not be possible; if this ever flips, re-derive the "
        "real three-way tenant-isolation assertions instead of this guard"
    )
    assert summary["tenant_a_did"].startswith("did:web:")
    assert summary["tenant_b_did"].startswith("did:web:")


async def test_s11_revocation(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s11_revocation")
    summary = assert_run_complete(result)
    assert_not_degraded(summary, "s11_revocation")
    assert summary["revoked"] is True
    assert isinstance(summary["minted_jti"], str) and summary["minted_jti"]
    # S11 never surfaces its published ctx_id in RunResult.contexts (always
    # []) — nothing to independently re-fetch here.
    assert result["contexts"] == []


async def test_s12_key_rotation(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s12_key_rotation")
    summary = assert_run_complete(result)
    assert summary["window_ok"] is True
    assert summary["active_before"] == 1
    assert summary["active_overlap"] == 2
    assert summary["active_after"] == 1
    # Under make up-full with a real admin token, the reload call should
    # actually run rather than being skipped.
    assert summary["cp_reload"] != "skipped (no control plane / admin token)"


async def test_s13_policy_deny(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s13_policy_deny")
    summary = assert_run_complete(result)
    assert summary["degraded"] is False, (
        "S13 must exercise the real control plane under make up-full"
    )
    assert summary["denied_unauthenticated"] is True
    assert summary["allowed_with_admin"] is True
    assert summary["anonymous_status"] in (401, 403)
    assert summary["admin_status"] == 200


async def test_s14_domain_pack(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s14_domain_pack")
    summary = assert_run_complete(result)
    assert summary["degraded"] is False, (
        "S14 must exercise the real control plane under make up-full"
    )
    assert isinstance(summary["base_type_status"], int) and 200 <= summary["base_type_status"] < 300
    packs = summary.get("packs") or []
    if packs:
        assert summary["unknown_type_status"] == 400, (
            f"domain packs {packs} are registered but the unknown-type ingest was not rejected"
        )


async def test_s15_supersession_lineage(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s15_supersession_lineage")
    summary = assert_run_complete(result)
    assert summary["v1_guard_rejected"] is True
    assert summary["same_lineage"] is True
    assert summary["v2_version"] >= 2
    assert len(result["contexts"]) == 2
    v1, v2 = result["contexts"]
    assert summary["current_ctx_id"] == v2
    v1_full = await deep_verify(settings.registry_a_url, v1, settings=settings, expect_receipt=True)
    await deep_verify(settings.registry_a_url, v2, settings=settings, expect_receipt=True)
    lineage_id = v1_full["body"]["lineage_id"]
    async with AcdpClient(settings.registry_a_url) as client:
        current = await client.current(lineage_id)
        assert current.body.ctx_id == v2


async def test_s16_dataref_ssrf(http: httpx.AsyncClient, settings: Settings) -> None:
    """Fully offline — no live-stack signal, included for full-catalog coverage."""
    result = await run_scenario(http, "s16_dataref_ssrf")
    summary = assert_run_complete(result)
    guard = summary["ssrf_guard"]
    assert guard["imds"].startswith("blocked:")
    assert guard["mixed_answer"].startswith("blocked:")
    assert guard["cross_port_redirect"] == "refused"
    assert guard["http_scheme"].startswith("blocked:")
    assert guard["public_screen"] == "passed"
    assert result["contexts"] == []


async def test_s17_supersession_authz(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s17_supersession_authz")
    summary = assert_run_complete(result)
    assert_not_degraded(summary, "s17_supersession_authz")
    assert summary["attacker_blocked"] is True
    assert summary["rejection_reason"] is not None
    assert len(result["contexts"]) == 1
    owner_ctx = result["contexts"][0]
    assert summary["owner_ctx"] == owner_ctx
    await deep_verify(settings.registry_a_url, owner_ctx, settings=settings, expect_receipt=True)


async def test_s18_idempotency(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s18_idempotency")
    summary = assert_run_complete(result)
    assert_not_degraded(summary, "s18_idempotency")
    assert summary["replayed"] is True
    assert summary["first_ctx"] == summary["second_ctx"]
    assert result["contexts"] == [summary["first_ctx"]]
    await deep_verify(
        settings.registry_a_url, summary["first_ctx"], settings=settings, expect_receipt=True
    )


async def test_s19_cp_did_web_p256(http: httpx.AsyncClient, settings: Settings) -> None:
    """Fully offline — no live-stack signal, included for full-catalog coverage."""
    result = await run_scenario(http, "s19_cp_did_web_p256")
    summary = assert_run_complete(result)
    assert summary["vm_type"] == "JsonWebKey2020"
    assert summary["jwk_only"] is True
    assert summary["jwk_curve"] == "P-256"
    assert "publicKeyMultibase" not in summary["verification_method"]
    assert summary["cp_resolvable"] is True
    assert result["contexts"] == []


async def test_s20_reserved_tenant(http: httpx.AsyncClient, settings: Settings) -> None:
    """Fully offline — no live-stack signal, included for full-catalog coverage."""
    result = await run_scenario(http, "s20_reserved_tenant")
    summary = assert_run_complete(result)
    guard = summary["reserved_tenant_guard"]
    assert guard["guard"] == "blocked"
    assert guard["untenanted"] == "allowed"
    assert guard["real_tenant"] == "allowed"
    assert guard["client_ctor"] == "blocked"
    assert guard["cp_bridge"] == "blocked"
    assert result["contexts"] == []


async def test_s21_capabilities_p256(http: httpx.AsyncClient, settings: Settings) -> None:
    """Fully offline — no live-stack signal, included for full-catalog coverage."""
    result = await run_scenario(http, "s21_capabilities_p256")
    summary = assert_run_complete(result)
    assert summary["algorithm"] == "ecdsa-p256"
    assert summary["signature_verified"] is True
    assert summary["cp_acceptable"] is True
    assert summary["signing_input"].startswith("acdp-cap:v1:")
    assert result["contexts"] == []


# ── S22-S34: receipts, tamper-resistance, transparency log, lifecycle ───────


async def test_s22_receipts(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s22_receipts")
    summary = assert_run_complete(result)
    assert_not_degraded(summary, "s22_receipts")
    assert summary["offline_publish_verified"] is True
    assert summary["registry_round_trip"] == "verified"
    assert summary["receipt_present"] is True
    assert summary["receipt_verified"] is True
    assert summary["body_offline_verified"] is True
    assert summary["authority_binding_ok"] is True
    assert summary["origin_binding_ok"] is True
    assert summary["require_policy_fail_closed"] is True
    assert len(result["contexts"]) == 1
    await deep_verify(
        settings.registry_a_url, result["contexts"][0], settings=settings, expect_receipt=True
    )


async def test_s23_receipt_tamper(http: httpx.AsyncClient, settings: Settings) -> None:
    """No live-stack signal even under make up-full (see module docstring)."""
    result = await run_scenario(http, "s23_receipt_tamper")
    summary = assert_run_complete(result)
    assert summary["all_failed_closed"] is True
    checks = summary["checks"]
    expected_cases = {
        "missing_receipt",
        "mutated_created_at",
        "mismatched_fingerprint",
        "rebound_ctx_id",
        "mismatched_content_hash",
        "forged_signature",
        "rebound_lineage_id",
        "rebound_origin_registry",
        "substituted_body",
    }
    assert set(checks) == expected_cases
    for name, outcome in checks.items():
        assert outcome["rejected"] is True, f"S23 case {name!r} was NOT rejected: {outcome}"
    assert "body lineage_id" in checks["rebound_lineage_id"]["why"]
    assert "body origin_registry" in checks["rebound_origin_registry"]["why"]
    assert "ctx_id binding mismatch" in checks["substituted_body"]["why"]


async def test_s24_historical_key(http: httpx.AsyncClient, settings: Settings) -> None:
    """Reuses a fixed, non-run-scoped pinned did:web identity — see module docstring."""
    result = await run_scenario(http, "s24_historical_key")
    summary = assert_run_complete(result)
    assert summary["offline_core_ok"] is True
    for key in (
        "rotation_distinct",
        "pre_rotation_verifies_under_old_key",
        "new_key_rejects_old_signature",
        "historically_authorized",
        "resolved_as_historical",
        "stripped_receipt_fail_closed",
        "removed_key_fail_closed",
    ):
        assert summary[key] is True, f"S24 {key} was not True: {summary}"
    assert summary["registry_round_trip"] == "verified", (
        f"S24 live round-trip did not verify (check config/registry-a.toml's "
        f"pinned 'rotating-historical' key material is still in sync with "
        f"the scenario's fixed seed label): {summary['registry_round_trip']}"
    )
    assert summary["receipt_records_publish_key"] is True
    assert len(result["contexts"]) == 1
    ctx_id = result["contexts"][0]
    assert_conformant_ctx(ctx_id, expected_authority=settings.registry_a_authority)
    # did:web signer — this harness cannot resolve *.playground.local DNS, so
    # only the receipt-binding half of deep_verify applies here.
    await deep_verify(settings.registry_a_url, ctx_id, settings=settings, expect_receipt=True)


async def test_s25_did_key(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s25_did_key")
    summary = assert_run_complete(result)
    n = summary["agent_count"]
    assert n == 3
    assert summary["offline_verified"] == n
    assert summary["tamper_rejected"] is True
    assert summary["rotation_is_new_identity"] is True
    assert summary["offline_core_ok"] is True
    # Unlike S9/S22/S24, S25's own code never assigns the literal string
    # "verified" to registry_round_trip on success — its only success value
    # is f"published_{len(published)}" (confirmed by reading
    # s25_did_key.py:100-177: no "verified" assignment exists in the file).
    # The real live-success signal is retrieved_verified_offline == n below
    # plus the absence of summary["degraded"], both asserted here.
    assert summary["registry_round_trip"] == f"published_{n}", (
        f"S25 live round-trip did not complete as expected: {summary['registry_round_trip']}"
    )
    assert summary["retrieved_verified_offline"] == n
    assert summary["supersede_outcome"] != "accepted_cross_identity_supersede", (
        "registry accepted a rotated did:key's cross-identity supersede attempt"
    )
    assert summary["supersede_rejected"] is True
    assert summary.get("degraded") is not True
    assert len(result["contexts"]) == n
    for ctx in result["contexts"]:
        assert_conformant_ctx(ctx, expected_authority=settings.registry_a_authority)
        await deep_verify(settings.registry_a_url, ctx, settings=settings, expect_receipt=True)


async def test_s26_divergence(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s26_divergence")
    summary = assert_run_complete(result)
    assert_not_degraded(summary, "s26_divergence")
    assert summary["version_hashes_differ"] is True
    assert summary["version_cause_identified"] is True
    assert summary["preimage_diff_localized"] is True
    assert summary["diagnostics_ok"] is True
    assert summary["registry_rejection"] != "accepted_tampered_body", (
        "registry-a accepted a deliberately non-reproducible tampered body"
    )
    assert summary["rejected_as_hash_mismatch"] is True, (
        f"expected a clean 400 hash_mismatch rejection, got {summary['registry_rejection']}"
    )
    assert result["contexts"] == []


async def test_s27_receipt_key_rotation(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s27_receipt_key_rotation")
    summary = assert_run_complete(result)
    assert summary["offline_core_ok"] is True
    assert summary["historical_receipt_verified"] is True
    assert summary["historical_status"] == "verified_historical"
    assert summary["current_receipt_verified"] is True
    assert summary["current_status"] == "verified"
    assert summary["removed_key_fail_closed"] is True
    assert summary["downgrade_rejected"] is True
    assert summary["tampered_historical_rejected"] is True
    assert summary["cross_bound_body_rejected"] is True
    assert "body created_at" in summary["cross_bound_body_why"]
    assert summary["live_round_trip"] == "verified", (
        f"S27 live round-trip did not verify: {summary['live_round_trip']}"
    )
    assert summary["live_receipt_status"] == "verified"
    assert len(result["contexts"]) == 1
    await deep_verify(
        settings.registry_a_url, result["contexts"][0], settings=settings, expect_receipt=True
    )


async def test_s28_lifecycle_retraction(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s28_lifecycle_retraction")
    summary = assert_run_complete(result)
    assert summary["offline_core_ok"] is True
    for key in (
        "event_verified",
        "replay_rejected",
        "tamper_rejected",
        "unsigned_rejected",
        "derivation_ok",
        "authz_check_ok",
    ):
        assert summary[key] is True, f"S28 {key} was not True: {summary}"
    assert summary["live_round_trip"] == "verified", (
        f"S28 live round-trip did not verify: {summary['live_round_trip']}"
    )
    for key in (
        "retracted_status_ok",
        "body_still_retrievable",
        "served_events_verified",
        "search_excludes_retracted",
        "current_head_excluded",
        "double_retract_conflict",
        "republished_active_ok",
        "current_restored",
    ):
        assert summary[key] is True, f"S28 {key} was not True: {summary}"
    assert len(result["contexts"]) == 2
    ctx_v1, ctx_v2 = result["contexts"]
    v1_full = await deep_verify(
        settings.registry_a_url, ctx_v1, settings=settings, expect_receipt=True
    )
    v2_full = await deep_verify(
        settings.registry_a_url, ctx_v2, settings=settings, expect_receipt=True
    )
    assert v2_full["registry_state"]["status"] == "active", (
        "S28 leaves v2 retracted+republished — the FINAL registry state must read active"
    )
    lineage_id = v1_full["body"]["lineage_id"]
    async with AcdpClient(settings.registry_a_url) as client:
        current = await client.current(lineage_id)
        assert current.body.ctx_id == ctx_v2
        assert current.registry_state.status == "active"


async def test_s29_transparency_log(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s29_transparency_log")
    summary = assert_run_complete(result)
    assert summary["offline_core_ok"] is True
    for key in (
        "checkpoints_verified",
        "inclusion_verified",
        "consistency_verified",
        "tamper_fail_closed",
    ):
        assert summary[key] is True, f"S29 {key} was not True: {summary}"
    assert summary["live_round_trip"] == "verified", (
        f"S29 live round-trip did not verify: {summary['live_round_trip']}"
    )
    for key in (
        "live_checkpoint_verified",
        "live_inclusion_verified",
        "live_consistency_verified",
        "live_tamper_fail_closed",
    ):
        assert summary[key] is True, f"S29 {key} was not True: {summary}"
    assert len(result["contexts"]) == 2
    for ctx in result["contexts"]:
        await deep_verify(settings.registry_a_url, ctx, settings=settings, expect_receipt=True)
    # Independent re-check of the FINAL transparency-log state: fetch a fresh
    # checkpoint ourselves and confirm the tree has grown to cover both
    # publishes made in this run. `verify_log_checkpoint` needs the
    # registry's resolved DID document to check the signature, which this
    # playground's *.playground.local registry DID isn't web-hosted to
    # provide (the scenario itself builds one from the shared seed rather
    # than resolving it — see its own AcdpDidDocument construction) — that
    # signature path is already exercised by the scenario's own
    # `live_checkpoint_verified`/`live_inclusion_verified` assertions above,
    # so this check adds the one thing those can't: proof the log actually
    # grew, straight from a client this run never touched.
    async with AcdpClient(settings.registry_a_url) as client:
        checkpoint = await client.log_checkpoint()
    assert isinstance(checkpoint.get("tree_size"), int) and checkpoint["tree_size"] >= 2


async def test_s30_head_receipt_freshness(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s30_head_receipt_freshness")
    summary = assert_run_complete(result)
    assert summary["offline_core_ok"] is True
    for key in (
        "fresh_ok",
        "stale_flag_ok",
        "future_rejected",
        "supersession_binding_ok",
        "tamper_rejected",
    ):
        assert summary[key] is True, f"S30 {key} was not True: {summary}"
    assert summary["live_round_trip"] == "verified", (
        f"S30 live round-trip did not verify: {summary['live_round_trip']}"
    )
    for key in ("live_v1_receipt_ok", "live_v2_receipt_ok", "live_replay_rejected"):
        assert summary[key] is True, f"S30 {key} was not True: {summary}"
    assert len(result["contexts"]) == 2
    ctx_v1, ctx_v2 = result["contexts"]
    v1_full = await deep_verify(
        settings.registry_a_url, ctx_v1, settings=settings, expect_receipt=True
    )
    await deep_verify(settings.registry_a_url, ctx_v2, settings=settings, expect_receipt=True)
    lineage_id = v1_full["body"]["lineage_id"]
    async with AcdpClient(settings.registry_a_url) as client:
        current = await client.current(lineage_id)
        assert current.body.ctx_id == ctx_v2
        assert current.lineage_head_receipt is not None, (
            "registry-a advertises head-receipts (RFC-ACDP-0011) — /current must carry one"
        )


async def test_s31_witness_cosigning(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s31_witness_cosigning")
    summary = assert_run_complete(result)
    assert summary["offline_core_ok"] is True
    assert summary["witness_did"].startswith("did:key:")
    for key in (
        "checkpoint_verified",
        "consistency_verified",
        "obligation_ok",
        "cosig_verified",
        "quorum_ok",
        "tamper_fail_closed",
    ):
        assert summary[key] is True, f"S31 {key} was not True: {summary}"
    assert summary["witnessed_count"] == 1
    assert summary["meets_quorum"] is True
    assert summary["live_round_trip"] == "verified", (
        f"S31 live round-trip did not verify: {summary['live_round_trip']}"
    )
    for key in (
        "live_obligation_ok",
        "live_cosig_verified",
        "live_quorum_ok",
        "live_tamper_fail_closed",
    ):
        assert summary[key] is True, f"S31 {key} was not True: {summary}"
    assert len(result["contexts"]) == 2
    for ctx in result["contexts"]:
        await deep_verify(settings.registry_a_url, ctx, settings=settings, expect_receipt=True)


async def test_s32_key_revocation(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s32_key_revocation")
    summary = assert_run_complete(result)
    assert summary["producer_did_method"] == "did:web"
    assert summary["offline_core_ok"] is True
    for key in (
        "rotation_distinct",
        "revocation_verified",
        "trust_class_producer_signed",
        "pre_compromise_authorized",
        "post_compromise_fail_closed",
        "no_receipt_fail_closed",
        "self_signed_rejected",
    ):
        assert summary[key] is True, f"S32 {key} was not True: {summary}"
    assert summary["trust_class"] == "producer_signed"
    assert summary["live_round_trip"] == "verified", (
        f"S32 live round-trip did not verify: {summary['live_round_trip']}"
    )
    for key in (
        "live_type_admitted",
        "live_revocation_parsed",
        "live_pre_compromise",
        "live_post_fail_closed",
    ):
        assert summary[key] is True, f"S32 {key} was not True: {summary}"
    # victim context (did:web) + the key-revocation context itself, both real
    # publishes to registry-a.
    assert len(result["contexts"]) >= 1
    for ctx in result["contexts"]:
        assert_conformant_ctx(ctx, expected_authority=settings.registry_a_authority)
        # did:web signers — only the receipt-binding half of deep_verify
        # applies (see S24's test for the same reasoning).
        await deep_verify(settings.registry_a_url, ctx, settings=settings, expect_receipt=True)


async def test_s33_anchors(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s33_anchors")
    summary = assert_run_complete(result)
    assert summary["offline_core_ok"] is True
    assert summary["anc001_well_formed_anchor_verified"] is True
    assert summary["anc005_scheme_unaware_verified"] is True
    assert summary["tamper_rejected"] is True
    assert summary["anchor_uri_dereferenced"] is False, (
        "a scheme-unaware verifier must never dereference anchors[].uri"
    )
    # S33's own code never assigns "verified" on success — only "published_3"
    # (confirmed in s33_anchors.py: registry_outcome's one success value is
    # the literal "published_3"). retrieved_anchors_match/carry_forward_ok/
    # clear_anchors_ok below are the real live-success signal.
    assert summary["registry_round_trip"] == "published_3", (
        f"S33 live round-trip did not complete as expected: {summary['registry_round_trip']}"
    )
    assert summary["retrieved_anchors_match"] is True
    assert summary["carry_forward_ok"] is True
    assert summary["clear_anchors_ok"] is True
    assert len(result["contexts"]) == 3
    ctx1, ctx2, ctx3 = result["contexts"]
    full1 = await deep_verify(settings.registry_a_url, ctx1, settings=settings, expect_receipt=True)
    full2 = await deep_verify(settings.registry_a_url, ctx2, settings=settings, expect_receipt=True)
    full3 = await deep_verify(settings.registry_a_url, ctx3, settings=settings, expect_receipt=True)
    assert full1["body"].get("anchors"), "S33 v1 must carry the well-formed anchor"
    assert full2["body"].get("anchors") == full1["body"].get("anchors"), (
        "S33 v2 (implicit carry-forward supersede) must inherit v1's anchors verbatim"
    )
    assert not full3["body"].get("anchors"), "S33 v3 (clear_anchors=True) must have none"


async def test_s34_embedded_content(http: httpx.AsyncClient, settings: Settings) -> None:
    result = await run_scenario(http, "s34_embedded_content")
    summary = assert_run_complete(result)
    assert summary["offline_core_ok"] is True
    assert summary["encodings_verified"] == ["json", "utf8", "base64"]
    for key in (
        "embedded_refs_verified",
        "served_body_verified",
        "encoding_preimages_distinct",
        "both_hashes_verified",
        "absent_content_hash_verified",
    ):
        assert summary[key] is True, f"S34 {key} was not True: {summary}"
    assert summary["utf8_wrong_preimage_rejected"] is True
    assert summary["foreign_root_hash_accepted"] is True
    assert summary["foreign_embedded_hash_rejected"] is True
    assert summary["root_embedded_independent"] is True
    assert summary["explicit_null_rejected"] is True
    assert summary["request_tamper_rejected"] is True
    assert summary["served_body_tamper_rejected"] is True
    # S34's own code never assigns "verified" on success — only "published_2"
    # (confirmed in s34_embedded_content.py: registry_outcome's one success
    # value is the literal "published_2"). live_body_verified/
    # live_refs_round_trip/live_carry_forward below are the real signal.
    assert summary["registry_round_trip"] == "published_2", (
        f"S34 live round-trip did not complete as expected: {summary['registry_round_trip']}"
    )
    assert summary["live_body_verified"] is True
    assert summary["live_refs_round_trip"] is True
    assert summary["live_carry_forward"] is True
    assert len(result["contexts"]) == 2
    ctx1, ctx2 = result["contexts"]
    full1 = await deep_verify(settings.registry_a_url, ctx1, settings=settings, expect_receipt=True)
    full2 = await deep_verify(settings.registry_a_url, ctx2, settings=settings, expect_receipt=True)
    assert full1["body"]["data_refs"], "S34 v1 must carry the 3 embedded data_refs"
    assert full2["body"]["data_refs"] == full1["body"]["data_refs"], (
        "S34 v2 (supersede omitting data_refs) must carry v1's embedded refs forward verbatim"
    )
