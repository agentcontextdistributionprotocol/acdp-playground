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
    monkeypatch.setenv("REGISTRY_C_URL", "http://127.0.0.1:1")
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
