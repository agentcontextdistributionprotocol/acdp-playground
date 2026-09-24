"""Live conformance — the playground's asserted contracts vs. the real binaries.

Each test wraps one probe from :mod:`playground.conformance` and runs it against
``make up-full``. These re-validate, against reality, the same contracts the
offline mock tests assert — the layer that would have caught the reserved-tenant
``422 → 400`` drift. Skipped unless ``ACDP_LIVE_STACK`` is set (see conftest).
"""

from __future__ import annotations

import httpx

from playground import conformance
from playground.conformance import LiveConfig


async def test_reserved_tenant_400(live_client: httpx.AsyncClient, live_config: LiveConfig):
    summary = await conformance.probe_reserved_tenant_400(live_client, live_config)
    assert "400" in summary


async def test_error_envelope_content_type(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_error_envelope_content_type(live_client, live_config)


async def test_ingest_body_limit_413(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_ingest_body_limit_413(live_client, live_config)


async def test_receipts_profile_advertised(live_client: httpx.AsyncClient, live_config: LiveConfig):
    summary = await conformance.probe_receipts_profile_advertised(live_client, live_config)
    # The probe enforces a minimum acdp_version, not an allowlist of spec lines —
    # any version >= the floor passes, so just confirm the probe ran and reported one.
    assert "acdp_version=" in summary


async def test_did_key_method_advertised(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_did_key_method_advertised(live_client, live_config)


async def test_served_ctx_id_binding(live_client: httpx.AsyncClient, live_config: LiveConfig):
    """RFC-ACDP-0006 §4.1 step 7 against the real binary.

    The client now refuses any retrieval whose served ``body.ctx_id`` differs
    from the requested one, so a registry that stopped honoring this would turn
    every playground run into a ``CtxIdBindingError``. This says which side is
    at fault.
    """
    summary = await conformance.probe_served_ctx_id_binding(live_client, live_config)
    assert "acdp://" in summary


async def test_media_type_gate(live_client: httpx.AsyncClient, live_config: LiveConfig):
    """RFC-ACDP-0007 §4.1 against the real binary — both directions.

    The accept half is the one that matters here: ``AcdpClient`` labels every
    request ``application/json``, so a registry that narrowed its accept-set
    would break every publish at once while a reject-only probe stayed green.
    """
    summary = await conformance.probe_media_type_gate(live_client, live_config)
    assert "415 unsupported_media_type" in summary
    assert "absent header accepted" in summary


async def test_interim_revocation_type_rejected(
    live_client: httpx.AsyncClient, live_config: LiveConfig
):
    """RFC-ACDP-0014 §10: the interim ``acdp:key-revocation`` spelling is
    retired. S32 publishes the modern form, so only this probe would notice a
    registry that started accepting the interim one again."""
    summary = await conformance.probe_interim_revocation_type_rejected(live_client, live_config)
    assert "400 schema_violation" in summary


async def test_anchors_require_0_5_0(live_client: httpx.AsyncClient, live_config: LiveConfig):
    """RFC-ACDP-0016 §14: anchors under a sub-0.5.0 declared ``acdp_version``
    are refused. S33 only ever publishes the accepted side."""
    summary = await conformance.probe_anchors_require_0_5_0(live_client, live_config)
    assert "400 schema_violation" in summary


# ── 0.3.0 endpoint contracts (RFC-ACDP-0011/0012/0013) ──────────────────────


async def test_log_checkpoint_signed(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_log_checkpoint_signed(live_client, live_config)


async def test_log_proof_inclusion_and_consistency(
    live_client: httpx.AsyncClient, live_config: LiveConfig
):
    await conformance.probe_log_proof_inclusion_and_consistency(live_client, live_config)


async def test_head_receipt_on_current(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_head_receipt_on_current(live_client, live_config)


async def test_retract_endpoint_fails_closed(
    live_client: httpx.AsyncClient, live_config: LiveConfig
):
    await conformance.probe_retract_endpoint_fails_closed(live_client, live_config)


async def test_cp_events_limit_capped(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_cp_events_cap(live_client, live_config)


async def test_cp_revocations_shape(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_cp_revocations_shape(live_client, live_config)


async def test_cp_pinned_keys_reload(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_cp_pinned_keys_reload(live_client, live_config)


async def test_capability_p256_algorithm_accepted(
    live_client: httpx.AsyncClient, live_config: LiveConfig
):
    await conformance.probe_capability_algorithm_accepted(live_client, live_config)
