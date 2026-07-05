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
    # The stack's registries may run either Final spec line (0.2.0 or 0.3.0).
    assert "0.2.0" in summary or "0.3.0" in summary


async def test_did_key_method_advertised(live_client: httpx.AsyncClient, live_config: LiveConfig):
    await conformance.probe_did_key_method_advertised(live_client, live_config)


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
