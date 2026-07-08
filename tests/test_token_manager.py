"""TokenManager: cache, single-flight, refresh, error taxonomy."""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from acdp import AcdpProducer
from acdp_client.token_manager import (
    CachedToken,
    ChallengeError,
    RefreshReason,
    TokenIssueError,
    TokenManager,
)


def _producer() -> AcdpProducer:
    return AcdpProducer.from_seed(
        bytes(range(32)),
        "did:web:registry.test:agents:alice",
        "did:web:registry.test:agents:alice#key-1",
    )


def _make_handler(
    *,
    challenge_status: int = 200,
    token_status: int = 200,
    token_ttl: int = 300,
    counter: dict[str, int] | None = None,
):
    """Build a stub httpx handler that simulates a registry's auth flow.

    Bumps ``counter['challenges']`` / ``counter['tokens']`` so tests can
    assert single-flight behavior.
    """

    if counter is None:
        counter = {"challenges": 0, "tokens": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/challenge":
            counter["challenges"] += 1
            if challenge_status != 200:
                return httpx.Response(challenge_status, text="challenge denied", request=request)
            expires_at = int(time.time()) + 120
            body = {
                "nonce": f"n-{counter['challenges']}",
                "registry_authority": "registry.test",
                "expires_at": expires_at,
                "signing_input": f"acdp-registry-auth:v1:n-{counter['challenges']}:"
                f"did:web:registry.test:agents:alice:registry.test:{expires_at}",
            }
            return httpx.Response(200, json=body, request=request)
        if request.url.path == "/auth/token":
            counter["tokens"] += 1
            if token_status != 200:
                return httpx.Response(token_status, text="token denied", request=request)
            body = {
                "token": f"jwt-token-{counter['tokens']}",
                "token_type": "Bearer",
                "expires_at": int(time.time()) + token_ttl,
            }
            return httpx.Response(200, json=body, request=request)
        return httpx.Response(404, request=request)

    return handler, counter


@pytest.mark.asyncio
async def test_token_for_runs_full_flow_and_caches():
    handler, counter = _make_handler()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    p = _producer()

    t1 = await tm.token_for(p, "http://registry.test")
    assert isinstance(t1, CachedToken)
    assert t1.token.startswith("jwt-token-")
    assert counter == {"challenges": 1, "tokens": 1}

    # Second call is cached.
    t2 = await tm.token_for(p, "http://registry.test")
    assert t2 is t1
    assert counter == {"challenges": 1, "tokens": 1}


@pytest.mark.asyncio
async def test_concurrent_token_for_is_single_flight():
    """20 simultaneous callers must trigger exactly one mint round trip."""
    handler, counter = _make_handler()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    p = _producer()

    results = await asyncio.gather(*(tm.token_for(p, "http://registry.test") for _ in range(20)))
    assert all(r is results[0] for r in results)
    assert counter == {"challenges": 1, "tokens": 1}


@pytest.mark.asyncio
async def test_invalidate_forces_refresh():
    handler, counter = _make_handler()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    p = _producer()

    await tm.token_for(p, "http://registry.test")
    tm.invalidate(p, "http://registry.test")
    await tm.token_for(p, "http://registry.test")
    assert counter == {"challenges": 2, "tokens": 2}


@pytest.mark.asyncio
async def test_expiring_token_is_refreshed_proactively():
    """Token issued with TTL < leeway should refresh on the next call."""
    handler, counter = _make_handler(token_ttl=1)  # 1s TTL
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http, leeway_seconds=30)  # 30s leeway > 1s TTL
    p = _producer()

    await tm.token_for(p, "http://registry.test")
    # Cached token is "fresh" by clock but inside the leeway window → refresh.
    await tm.token_for(p, "http://registry.test")
    assert counter == {"challenges": 2, "tokens": 2}


@pytest.mark.asyncio
async def test_challenge_failure_raises_challenge_error():
    handler, _ = _make_handler(challenge_status=500)
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    p = _producer()

    with pytest.raises(ChallengeError) as exc:
        await tm.token_for(p, "http://registry.test")
    assert "500" in str(exc.value)


@pytest.mark.asyncio
async def test_token_failure_raises_token_issue_error():
    handler, _ = _make_handler(token_status=401)
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    p = _producer()

    with pytest.raises(TokenIssueError) as exc:
        await tm.token_for(p, "http://registry.test")
    assert "401" in str(exc.value)


@pytest.mark.asyncio
async def test_different_registries_get_separate_tokens():
    handler, counter = _make_handler()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    p = _producer()

    a = await tm.token_for(p, "http://reg-a.test")
    b = await tm.token_for(p, "http://reg-b.test")
    assert a is not b
    assert counter["tokens"] == 2


# ── refresh-reason telemetry ─────────────────────────────────────────────


def _mint_success_records(caplog: pytest.LogCaptureFixture) -> list:
    """All `acdp.token.mint.success` records captured so far."""
    return [r for r in caplog.records if getattr(r, "event", None) == "acdp.token.mint.success"]


def _mint_start_records(caplog: pytest.LogCaptureFixture) -> list:
    return [r for r in caplog.records if getattr(r, "event", None) == "acdp.token.mint.start"]


@pytest.mark.asyncio
async def test_first_mint_logs_first_use_reason(caplog: pytest.LogCaptureFixture):
    caplog.set_level("INFO", logger="acdp_client.token_manager")
    handler, _ = _make_handler()
    tm = TokenManager(http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    p = _producer()

    await tm.token_for(p, "http://registry.test")

    successes = _mint_success_records(caplog)
    assert len(successes) == 1
    assert successes[0].refresh_reason == RefreshReason.FIRST_USE.value
    assert successes[0].agent_did == p.agent_did
    assert successes[0].registry_base_url == "http://registry.test"
    assert successes[0].ttl_seconds > 0
    assert successes[0].elapsed_ms >= 0

    # The matching start record carries the same reason.
    starts = _mint_start_records(caplog)
    assert len(starts) == 1
    assert starts[0].refresh_reason == RefreshReason.FIRST_USE.value


@pytest.mark.asyncio
async def test_stale_cache_logs_proactive_refresh(caplog: pytest.LogCaptureFixture):
    caplog.set_level("INFO", logger="acdp_client.token_manager")
    # token_ttl=1s, leeway=30s → second call sees the cached token as stale
    handler, _ = _make_handler(token_ttl=1)
    tm = TokenManager(
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        leeway_seconds=30,
    )
    p = _producer()

    await tm.token_for(p, "http://registry.test")  # FIRST_USE
    caplog.clear()
    await tm.token_for(p, "http://registry.test")  # PROACTIVE_REFRESH

    successes = _mint_success_records(caplog)
    assert len(successes) == 1
    assert successes[0].refresh_reason == RefreshReason.PROACTIVE_REFRESH.value


@pytest.mark.asyncio
async def test_invalidate_then_mint_logs_reactive_401(caplog: pytest.LogCaptureFixture):
    caplog.set_level("INFO", logger="acdp_client.token_manager")
    handler, _ = _make_handler()
    tm = TokenManager(http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    p = _producer()

    await tm.token_for(p, "http://registry.test")  # FIRST_USE
    caplog.clear()
    tm.invalidate(p, "http://registry.test")  # default reason = REACTIVE_401
    await tm.token_for(p, "http://registry.test")

    successes = _mint_success_records(caplog)
    assert len(successes) == 1
    assert successes[0].refresh_reason == RefreshReason.REACTIVE_401.value


@pytest.mark.asyncio
async def test_invalidate_pending_reason_is_consumed_once(
    caplog: pytest.LogCaptureFixture,
):
    """A pending REACTIVE_401 should apply to the *next* mint only.

    Subsequent mints (after the cache refills and goes stale again)
    must fall back to PROACTIVE_REFRESH; the explicit reason is not
    sticky.
    """
    caplog.set_level("INFO", logger="acdp_client.token_manager")
    handler, _ = _make_handler(token_ttl=1)
    tm = TokenManager(
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        leeway_seconds=30,
    )
    p = _producer()

    await tm.token_for(p, "http://registry.test")  # FIRST_USE
    tm.invalidate(p, "http://registry.test")
    await tm.token_for(p, "http://registry.test")  # REACTIVE_401 (consumed)
    caplog.clear()
    await tm.token_for(p, "http://registry.test")  # stale → PROACTIVE_REFRESH

    successes = _mint_success_records(caplog)
    assert len(successes) == 1
    assert successes[0].refresh_reason == RefreshReason.PROACTIVE_REFRESH.value


@pytest.mark.asyncio
async def test_explicit_invalidate_reason_overrides_default(
    caplog: pytest.LogCaptureFixture,
):
    """`invalidate(reason=...)` lets callers signal admin-driven rotations
    distinctly from server-driven 401s."""
    caplog.set_level("INFO", logger="acdp_client.token_manager")
    handler, _ = _make_handler()
    tm = TokenManager(http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    p = _producer()

    await tm.token_for(p, "http://registry.test")
    caplog.clear()
    tm.invalidate(p, "http://registry.test", reason=RefreshReason.PROACTIVE_REFRESH)
    await tm.token_for(p, "http://registry.test")

    successes = _mint_success_records(caplog)
    assert len(successes) == 1
    assert successes[0].refresh_reason == RefreshReason.PROACTIVE_REFRESH.value


@pytest.mark.asyncio
async def test_failed_mint_logs_failure_with_kind(caplog: pytest.LogCaptureFixture):
    caplog.set_level("INFO", logger="acdp_client.token_manager")
    handler, _ = _make_handler(token_status=401)
    tm = TokenManager(http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    p = _producer()

    with pytest.raises(TokenIssueError):
        await tm.token_for(p, "http://registry.test")

    failures = [r for r in caplog.records if getattr(r, "event", None) == "acdp.token.mint.failure"]
    assert len(failures) == 1
    assert failures[0].failure_kind == "token_status"
    assert failures[0].refresh_reason == RefreshReason.FIRST_USE.value
    assert "401" in failures[0].detail
