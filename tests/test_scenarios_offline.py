"""Offline assertions for the auth-dependent and 0.2 trust scenarios.

Covers S9–S14, S18, S21 (auth-dependent) and the ACDP 0.2 trust & hardening
set S22–S26 (receipts, did:key, historical keys, divergence diagnostics).

These scenarios can't complete token issuance against a stock registry (the
playground's ``*.playground.local`` DIDs aren't web-hosted and keys rotate per
run), so the docs' contract is: they **degrade gracefully** — completing with
``degraded: true`` rather than failing — while their deterministic crypto/window
cores still run. This suite pins both halves of that contract offline by
pointing the registries (and CP) at an unreachable port, mirroring the S16/S17/
S19/S20 offline tests.

S15 is intentionally absent: it hard-fails without a live registry (no graceful
degrade path), so it is covered by the live suite only.
"""

from __future__ import annotations

import asyncio

import pytest

from playground.config import get_settings
from playground.scenarios import get_scenario
from playground.scenarios.models import RunSpec


@pytest.fixture()
def offline_stack(monkeypatch):
    """Point every backend at an unreachable port so live calls fail fast and
    scenarios take their deterministic + degrade-gracefully paths."""
    monkeypatch.setenv("REGISTRY_A_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("REGISTRY_B_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("CONTROL_PLANE_URL", "")
    monkeypatch.setenv("LLM_PROVIDER", "mock")  # no langchain_openai in CI
    get_settings.cache_clear()
    try:
        yield
    finally:
        get_settings.cache_clear()


async def _run(scenario_id: str):
    scenario = get_scenario(scenario_id)
    assert scenario is not None
    q: asyncio.Queue = asyncio.Queue()
    return await scenario.run(RunSpec(run_id=f"r-{scenario_id}", scenario_id=scenario_id), q)


# ── deterministic crypto / window cores (complete, not degraded) ─────────


async def test_s9_p256_publish_crypto_core(offline_stack):
    res = await _run("s9_p256_publish")
    assert res.status == "complete"
    s = res.summary
    assert s["algorithm"] == "ecdsa-p256"
    assert s["local_signature_verified"] is True
    assert s["crypto_ok"] is True


async def test_s12_key_rotation_window_core(offline_stack):
    res = await _run("s12_key_rotation")
    assert res.status == "complete"
    s = res.summary
    assert s["window_ok"] is True
    # Rotation overlap: one key before, both during the overlap, one after.
    assert s["active_before"] == 1
    assert s["active_overlap"] == 2
    assert s["active_after"] == 1


async def test_s21_capabilities_p256_core(offline_stack):
    res = await _run("s21_capabilities_p256")
    assert res.status == "complete"
    s = res.summary
    assert s["algorithm"] == "ecdsa-p256"
    assert s["signature_verified"] is True
    assert s["cp_acceptable"] is True
    assert s["signing_input"].startswith("acdp-cap:v1:")


# ── ACDP 0.2 trust & hardening deterministic cores ───────────────────────


async def test_s22_receipts_offline_core(offline_stack):
    # No registry -> the receipt half degrades, but the did:key publish
    # request self-verifies offline (content_hash + embedded-key signature).
    res = await _run("s22_receipts")
    assert res.status == "complete"
    s = res.summary
    assert s["producer_did_method"] == "did:key"
    assert s["offline_publish_verified"] is True
    assert s.get("degraded") is True  # receipt verification needs a live registry


async def test_s23_receipt_tamper_fails_closed(offline_stack):
    # Fully deterministic: every dishonest receipt must be rejected.
    res = await _run("s23_receipt_tamper")
    assert res.status == "complete"
    s = res.summary
    assert s["all_failed_closed"] is True
    # Each adversarial class fired (missing, created_at, fingerprint, ctx_id,
    # content_hash, signature).
    assert all(c["rejected"] for c in s["checks"].values())
    assert len(s["checks"]) == 6


async def test_s24_historical_key_core(offline_stack):
    res = await _run("s24_historical_key")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    assert s["rotation_distinct"] is True
    assert s["pre_rotation_verifies_under_old_key"] is True
    assert s["new_key_rejects_old_signature"] is True
    assert s["historically_authorized"] is True
    # The §9 lifecycle is delegated to the SDK: the retained-but-retired key
    # resolves as historical, and the removed key fails closed via key_not_found.
    assert s["resolved_as_historical"] is True
    assert s["stripped_receipt_fail_closed"] is True
    assert s["removed_key_fail_closed"] is True


async def test_s25_did_key_offline_core(offline_stack):
    res = await _run("s25_did_key")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    assert s["offline_verified"] == s["agent_count"]
    assert s["tamper_rejected"] is True
    assert s["rotation_is_new_identity"] is True
    assert s.get("degraded") is True  # publish round-trip needs a live registry


async def test_s26_divergence_diagnostics_core(offline_stack):
    res = await _run("s26_divergence")
    assert res.status == "complete"
    s = res.summary
    assert s["diagnostics_ok"] is True
    assert s["version_hashes_differ"] is True
    assert s["version_cause_identified"] is True
    assert s["preimage_diff_localized"] is True
    assert s.get("degraded") is True  # hash_mismatch rejection needs a live registry


async def test_s27_receipt_key_rotation_core(offline_stack):
    res = await _run("s27_receipt_key_rotation")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    # Historical receipt resolves under the retired registry key (§9) and is
    # reported with the distinguishable verified_historical status.
    assert s["historical_receipt_verified"] is True
    assert s["historical_status"] == "verified_historical"
    assert s["current_receipt_verified"] is True
    assert s["current_status"] == "verified"
    # Removing the retired key, downgrading the algorithm, and tampering the
    # body binding all fail closed.
    assert s["removed_key_fail_closed"] is True
    assert s["downgrade_rejected"] is True
    assert s["tampered_historical_rejected"] is True
    assert s.get("degraded") is True  # live receipt round-trip needs a registry


# ── ACDP 0.3.0 (RFC-ACDP-0011/0012/0013) deterministic cores ─────────────


async def test_s28_lifecycle_retraction_core(offline_stack):
    res = await _run("s28_lifecycle_retraction")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    # RFC-ACDP-0013 §5: a signed retraction verifies; the ctx_id replay
    # binding, tamper detection and the MUST-be-signed rule all fail closed.
    assert s["event_verified"] is True
    assert s["replay_rejected"] is True
    assert s["tamper_rejected"] is True
    assert s["unsigned_rejected"] is True
    # §7.1: order-based derivation, last registered event wins, unknown
    # event types inert; plus the host-owned §4/§12 actor-authorization check.
    assert s["derivation_ok"] is True
    assert s["authz_check_ok"] is True
    assert s.get("degraded") is True  # live retract/republish needs a registry


async def test_s29_transparency_log_core(offline_stack):
    res = await _run("s29_transparency_log")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    # RFC-ACDP-0012 §9: signed checkpoints, rebuilt-leaf inclusion at two
    # tree sizes, and consistency against the retained first root all verify.
    assert s["checkpoints_verified"] is True
    assert s["inclusion_verified"] is True
    assert s["consistency_verified"] is True
    # §11: every tampered artifact (flipped path, flipped root, retained-root
    # rewrite, substituted embedded checkpoint) fails as invalid_log_proof.
    assert s["tamper_fail_closed"] is True
    assert s.get("degraded") is True  # live /log endpoints need a registry


async def test_s30_head_receipt_freshness_core(offline_stack):
    res = await _run("s30_head_receipt_freshness")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    # RFC-ACDP-0011 §6/§7: a fresh receipt verifies not-stale; staleness is
    # policy (valid + stale on an aged receipt); a future as_of fails; a
    # replayed pre-supersession receipt fails the head binding; tampering
    # breaks the signature.
    assert s["fresh_ok"] is True
    assert s["stale_flag_ok"] is True
    assert s["future_rejected"] is True
    assert s["supersession_binding_ok"] is True
    assert s["tamper_rejected"] is True
    assert s.get("degraded") is True  # live /current receipts need a registry


# ── ACDP 0.4 (RFC-ACDP-0015) deterministic core ──────────────────────────


async def test_s31_witness_cosigning_core(offline_stack):
    res = await _run("s31_witness_cosigning")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    # The witness discharges the §7 obligation before cosigning: the
    # checkpoint's own signature verifies and the log is consistent 1→2
    # against a retained root.
    assert s["checkpoint_verified"] is True
    assert s["consistency_verified"] is True
    assert s["obligation_ok"] is True
    # A did:key witness cosigns; the consumer verifies (§8) and the quorum is
    # 1-witnessed, meeting a min_witnesses=1 policy.
    assert s["witness_did_method"] == "did:key"
    assert s["witness_did"].startswith("did:key:")
    assert s["cosig_verified"] is True
    assert s["quorum_ok"] is True
    assert s["witnessed_count"] == 1
    assert s["meets_quorum"] is True
    # binding-detects-lies: a cosignature over a tampered root is refused as
    # invalid_witness_cosignature (§8 step 4) and earns no quorum credit.
    assert s["tamper_fail_closed"] is True
    assert s.get("degraded") is True  # live /log cosigning needs a registry


# ── ACDP 0.3.0 (RFC-ACDP-0014) key-revocation deterministic core ─────────


async def test_s32_key_revocation_core(offline_stack):
    res = await _run("s32_key_revocation")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    # A producer rotates K1→K2 and publishes a producer-signed key-revocation
    # context: it verifies under K2 and classifies producer_signed (§5).
    assert s["rotation_distinct"] is True
    assert s["revocation_verified"] is True
    assert s["trust_class"] == "producer_signed"
    assert s["trust_class_producer_signed"] is True
    # §7 compromise-boundary semantics against a receipt-attested publish time:
    # before T → historically authorized (pre-compromise); at/after T and no
    # receipt → fail closed.
    assert s["pre_compromise_authorized"] is True
    assert s["post_compromise_fail_closed"] is True
    assert s["no_receipt_fail_closed"] is True
    # §5 step 2: a revocation of K1 signed by K1 itself is rejected.
    assert s["self_signed_rejected"] is True
    assert s.get("degraded") is True  # live key-revocation publish needs a registry


# ── ACDP 0.5.0 (RFC-ACDP-0016) external anchors deterministic core ───────


async def test_s33_anchors_core(offline_stack):
    res = await _run("s33_anchors")
    assert res.status == "complete"
    s = res.summary
    assert s["offline_core_ok"] is True
    # anc-001: a well-formed, recognized-scheme anchor is accepted and
    # verifies like any other signed field.
    assert s["anc001_well_formed_anchor_verified"] is True
    # anc-005: a scheme-unaware verifier still produces a valid verdict.
    assert s["anc005_scheme_unaware_verified"] is True
    # A tampered anchor fails closed (anchors are signed byte-exactly).
    assert s["tamper_rejected"] is True
    # §6/§14: anchors[].uri is structurally never dereferenced — the DNS
    # trap around every verify call would have raised otherwise.
    assert s["anchor_uri_dereferenced"] is False
    assert s.get("degraded") is True  # live publish/supersede needs a registry


# ── graceful degradation contract (complete + degraded: true) ────────────


@pytest.mark.parametrize(
    "scenario_id",
    [
        "s10_tenant_isolation",
        "s11_revocation",
        "s13_policy_deny",
        "s14_domain_pack",
        "s18_idempotency",
    ],
)
async def test_auth_scenario_degrades_gracefully(offline_stack, scenario_id):
    res = await _run(scenario_id)
    # The documented contract: degrade, don't hard-fail.
    assert res.status == "complete"
    assert res.summary.get("degraded") is True
    assert res.error is None
