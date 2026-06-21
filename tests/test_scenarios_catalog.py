"""Catalog discovers every expected scenario and each is runnable.

This is the single authoritative inventory check — keep ``EXPECTED`` in sync
with ``playground/scenarios/catalog/``. The round-specific suites (round2/
round3) only spot-check their own newly-added ids, so the full list lives here.
"""

from __future__ import annotations

from playground.scenarios import list_scenarios

EXPECTED = {
    "s1_single_publish",
    "s2_producer_consumer",
    "s3_fanout",
    "s4_chain",
    "s5_cross_registry",
    "s6_restricted",
    "s7_supersession",
    "s8_cross_org",
    "s9_p256_publish",
    "s10_tenant_isolation",
    "s11_revocation",
    "s12_key_rotation",
    "s13_policy_deny",
    "s14_domain_pack",
    "s15_supersession_lineage",
    "s16_dataref_ssrf",
    "s17_supersession_authz",
    "s18_idempotency",
    "s19_cp_did_web_p256",
    "s20_reserved_tenant",
    "s21_capabilities_p256",
    # ACDP 0.2 trust & hardening (RFC-ACDP-0010): receipts, did:key,
    # historical keys, divergence diagnostics.
    "s22_receipts",
    "s23_receipt_tamper",
    "s24_historical_key",
    "s25_did_key",
    "s26_divergence",
    "s27_receipt_key_rotation",
}


def test_all_scenarios_load():
    got = {s.id for s in list_scenarios()}
    assert EXPECTED <= got, f"missing: {EXPECTED - got}"


def test_no_unexpected_scenarios():
    """New catalog files must be added to EXPECTED so the inventory stays a
    deliberate, reviewed list (catches accidental or duplicate ids)."""
    got = {s.id for s in list_scenarios()}
    assert got <= EXPECTED, f"unlisted scenarios discovered: {got - EXPECTED}"


def test_scenario_ids_are_unique():
    ids = [s.id for s in list_scenarios()]
    assert len(ids) == len(set(ids)), "duplicate scenario ids in catalog"


def test_every_scenario_has_runner():
    for s in list_scenarios():
        assert s.run is not None, f"{s.id} missing run()"
