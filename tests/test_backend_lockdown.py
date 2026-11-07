"""Backend lockdown: the x-api-key gate, client-IP trust, run launch limits,
LLM-call quotas and the registry passthrough.

Everything here runs offline: the registries are an ``httpx.MockTransport``
and scenario execution is replaced where a test only needs the launch path.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import ValidationError

from acdp_client.identifiers import synthetic_ctx_id
from acdp_client.models import StepEvent
from playground import quota as quota_mod
from playground.api import registry_proxy
from playground.api import runs as runs_api
from playground.config import Settings, get_settings
from playground.main import app
from playground.quota import (
    MemoryQuotaStore,
    QuotaDenial,
    QuotaGuardedLLM,
    RunQuotaContext,
    check_llm_quota,
    counters_for,
    current_run,
)
from playground.rate_limit import RunLimiter, RunLimitExceeded, run_limiter
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef
from playground.scenarios.runner import execute
from playground.security import ApiKeyMiddleware, key_matches

KEY = "k" * 43
GATE_DETAIL = "missing or invalid x-api-key"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fresh settings, limiter and quota store per test."""
    for var in (
        "PLAYGROUND_API_KEY",
        "PLAYGROUND_REQUIRE_API_KEY",
        "DATABASE_URL",
        "MAX_CONCURRENT_RUNS",
        "RUN_RATE_LIMIT_PER_IP",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DATABASE_URL", "")
    get_settings.cache_clear()
    run_limiter.active = 0
    run_limiter._launches.clear()
    quota_mod._store = None
    yield
    get_settings.cache_clear()
    run_limiter.active = 0
    run_limiter._launches.clear()
    quota_mod._store = None


def _settings(monkeypatch: pytest.MonkeyPatch, **env: Any) -> Settings:
    for k, v in env.items():
        monkeypatch.setenv(k.upper(), str(v))
    get_settings.cache_clear()
    return get_settings()


def _enforced(monkeypatch: pytest.MonkeyPatch, **env: Any) -> Settings:
    env.setdefault("webhook_secret", "test-webhook-secret")
    return _settings(monkeypatch, playground_api_key=KEY, playground_require_api_key="true", **env)


# ── the gate ────────────────────────────────────────────────────────────────

GATED = [
    ("GET", "/"),
    ("GET", "/docs"),
    ("GET", "/redoc"),
    ("GET", "/openapi.json"),
    ("GET", "/readyz"),
    ("GET", "/scenarios"),
    ("GET", "/scenarios/s1_single_publish"),
    ("POST", "/runs"),
    ("GET", "/runs/some-run"),
    ("GET", "/runs/some-run/events"),
    ("GET", f"/contexts/{synthetic_ctx_id('registry-a.playground.local', 'gate')}"),
    ("GET", "/registries/a/healthz"),
    ("GET", "/registries/b/.well-known/jwks.json"),
    ("GET", "/no-such-route"),
    ("GET", "/healthz/"),
]


@pytest.mark.parametrize(("method", "path"), GATED)
def test_every_route_but_two_requires_the_key(monkeypatch, method, path):
    _enforced(monkeypatch)
    with TestClient(app) as c:
        r = c.request(method, path, json={"scenario_id": "s1_single_publish"})
        assert r.status_code == 401, (method, path, r.text)
        assert r.json() == {"detail": GATE_DETAIL}
        assert "x-api-key" in r.headers["www-authenticate"]
        bad = c.request(method, path, headers={"x-api-key": KEY + "x"})
        assert bad.status_code == 401


def test_healthz_and_webhook_are_exempt(monkeypatch):
    _enforced(monkeypatch)
    with TestClient(app) as c:
        assert c.get("/healthz").status_code == 200
        # The webhook route runs its own HMAC check: a bad signature is
        # rejected by the handler, not by the key gate.
        r = c.post("/webhooks/acdp", content=b"{}", headers={"x-acdp-signature": "sha256=00"})
        assert not (r.status_code == 401 and r.content and r.json() == {"detail": GATE_DETAIL})


def test_valid_key_opens_gated_routes(monkeypatch):
    _enforced(monkeypatch)
    with TestClient(app) as c:
        h = {"x-api-key": KEY}
        assert c.get("/scenarios", headers=h).status_code == 200
        assert c.get("/openapi.json", headers=h).status_code == 200
        assert c.get("/docs", headers=h).status_code == 200


def test_not_enforced_lets_keyless_and_wrong_key_through(monkeypatch):
    _settings(monkeypatch, playground_api_key=KEY)
    with TestClient(app) as c:
        assert c.get("/scenarios").status_code == 200
        assert c.get("/scenarios", headers={"x-api-key": "wrong"}).status_code == 200


def test_cors_preflight_is_answered_before_the_gate(monkeypatch):
    _enforced(monkeypatch)
    with TestClient(app) as c:
        r = c.options(
            "/runs",
            headers={
                "origin": "https://console.example",
                "access-control-request-method": "POST",
                "access-control-request-headers": "x-api-key,content-type",
            },
        )
        assert r.status_code == 200
        assert "x-api-key" in r.headers["access-control-allow-headers"].lower()


def test_enforcement_without_a_key_refuses_to_start(monkeypatch):
    monkeypatch.setenv("PLAYGROUND_REQUIRE_API_KEY", "true")
    monkeypatch.setenv("PLAYGROUND_API_KEY", "")
    get_settings.cache_clear()
    with pytest.raises(ValidationError, match="PLAYGROUND_API_KEY is empty"):
        get_settings()
    with pytest.raises(ValidationError), TestClient(app):
        pass


def test_key_matches_is_strict():
    assert key_matches(KEY, KEY)
    assert not key_matches(KEY + "x", KEY)
    assert not key_matches(None, KEY)
    assert not key_matches("", "")  # an unset key never matches


# ── client IP trust ─────────────────────────────────────────────────────────


def _echo_app() -> FastAPI:
    echo = FastAPI()
    echo.add_middleware(ApiKeyMiddleware)

    @echo.get("/echo")
    async def _echo(request: Request) -> dict:
        s = request.state
        return {"ip": s.client_ip, "keyed": s.api_key_valid, "per_ip": s.per_ip_limits}

    return echo


def test_client_ip_header_trusted_only_with_the_key(monkeypatch):
    _settings(monkeypatch, playground_api_key=KEY)
    with TestClient(_echo_app()) as c:
        spoof = {"x-acdp-client-ip": "203.0.113.9"}
        keyless = c.get("/echo", headers=spoof).json()
        assert keyless == {"ip": "testclient", "keyed": False, "per_ip": False}
        wrong = c.get("/echo", headers={**spoof, "x-api-key": "nope"}).json()
        assert wrong["ip"] == "testclient" and not wrong["keyed"]
        keyed = c.get("/echo", headers={**spoof, "x-api-key": KEY}).json()
        assert keyed == {"ip": "203.0.113.9", "keyed": True, "per_ip": True}
        v6 = c.get("/echo", headers={"x-acdp-client-ip": "2001:DB8::1", "x-api-key": KEY}).json()
        assert v6["ip"] == "2001:db8::/64"  # IPv6 is bucketed per /64
        junk = c.get("/echo", headers={"x-acdp-client-ip": "not-an-ip", "x-api-key": KEY})
        assert junk.json()["ip"] == "testclient"


def test_per_ip_limits_apply_to_keyless_once_enforced(monkeypatch):
    _enforced(monkeypatch)
    with TestClient(_echo_app()) as c:
        assert c.get("/echo", headers={"x-api-key": KEY}).json()["per_ip"] is True


# ── run launch limits ───────────────────────────────────────────────────────


class _Launches:
    """Stands in for runner.execute: records the charged IP and blocks until released."""

    def __init__(self) -> None:
        self.ips: list[str | None] = []

    async def __call__(self, scenario, spec, queue, *, client_ip=None):
        self.ips.append(client_ip)
        await asyncio.sleep(3600)


def _drain(c: TestClient) -> None:
    async def cancel() -> None:
        tasks = list(runs_api._tasks)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    c.portal.call(cancel)


def _launch(c: TestClient, headers: dict | None = None) -> httpx.Response:
    return c.post("/runs", json={"scenario_id": "s1_single_publish"}, headers=headers or {})


def test_per_ip_launch_limit_with_retry_after(monkeypatch):
    _settings(monkeypatch, playground_api_key=KEY, max_concurrent_runs=100)
    fake = _Launches()
    monkeypatch.setattr(runs_api, "execute", fake)
    h = {"x-api-key": KEY, "x-acdp-client-ip": "198.51.100.7"}
    with TestClient(app) as c:
        try:
            assert [_launch(c, h).status_code for _ in range(5)] == [202] * 5
            r = _launch(c, h)
            assert r.status_code == 429
            assert r.json()["detail"]["code"] == "run_rate_limited"
            assert 1 <= int(r.headers["retry-after"]) <= 600
            # A different (trusted) client IP has its own bucket.
            other = {"x-api-key": KEY, "x-acdp-client-ip": "198.51.100.8"}
            assert _launch(c, other).status_code == 202
        finally:
            _drain(c)
    assert fake.ips[:5] == ["198.51.100.7"] * 5


def test_spoofed_client_ip_without_key_does_not_pick_a_bucket(monkeypatch):
    _settings(monkeypatch, playground_api_key=KEY, max_concurrent_runs=100)
    fake = _Launches()
    monkeypatch.setattr(runs_api, "execute", fake)
    with TestClient(app) as c:
        try:
            # Keyless while enforcement is off: no per-IP bucket at all (the
            # socket peer is the shared edge proxy), and the header is ignored.
            for i in range(8):
                assert _launch(c, {"x-acdp-client-ip": f"192.0.2.{i}"}).status_code == 202
        finally:
            _drain(c)
    assert fake.ips == [None] * 8


def test_keyed_requests_share_the_peer_bucket_without_the_header(monkeypatch):
    _enforced(monkeypatch, max_concurrent_runs=100)
    monkeypatch.setattr(runs_api, "execute", _Launches())
    with TestClient(app) as c:
        try:
            codes = [_launch(c, {"x-api-key": KEY}).status_code for _ in range(6)]
        finally:
            _drain(c)
    assert codes == [202] * 5 + [429]


def test_max_concurrent_runs(monkeypatch):
    _settings(monkeypatch, max_concurrent_runs=3)
    monkeypatch.setattr(runs_api, "execute", _Launches())
    with TestClient(app) as c:
        try:
            assert [_launch(c).status_code for _ in range(3)] == [202] * 3
            r = _launch(c)
            assert r.status_code == 429
            assert r.json()["detail"]["code"] == "max_concurrent_runs"
            assert r.headers["retry-after"] == "10"
        finally:
            _drain(c)
        assert run_limiter.active == 0
        assert _launch(c).status_code == 202
        _drain(c)


def test_unknown_scenario_does_not_consume_a_launch(monkeypatch):
    _settings(monkeypatch, playground_api_key=KEY, run_rate_limit_per_ip=1)
    monkeypatch.setattr(runs_api, "execute", _Launches())
    h = {"x-api-key": KEY}
    with TestClient(app) as c:
        try:
            assert c.post("/runs", json={"scenario_id": "nope"}, headers=h).status_code == 404
            assert _launch(c, h).status_code == 202
        finally:
            _drain(c)


def test_run_limiter_sliding_window(monkeypatch):
    _settings(
        monkeypatch,
        run_rate_limit_per_ip=2,
        run_rate_limit_window_seconds=60,
        max_concurrent_runs=10,
    )
    lim = RunLimiter()
    lim.acquire("ip", now=0)
    lim.acquire("ip", now=10)
    with pytest.raises(RunLimitExceeded) as e:
        lim.acquire("ip", now=20)
    assert e.value.retry_after == 40
    lim.acquire("ip", now=60.5)  # the first launch aged out
    lim.acquire(None, now=61)  # no IP: concurrency only
    assert lim.active == 4
    for _ in range(10):
        lim.release()
    assert lim.active == 0


# ── LLM quotas ──────────────────────────────────────────────────────────────


def test_counters_and_reset_times(monkeypatch):
    s = _settings(monkeypatch)
    now = datetime(2026, 12, 31, 23, 59, tzinfo=UTC)
    by = {c.quota: c for c in counters_for("10.0.0.1", s, now)}
    assert set(by) == {"global_daily", "global_monthly", "per_ip_daily", "per_ip_monthly"}
    assert by["per_ip_daily"].limit == 30 and by["per_ip_monthly"].limit == 300
    assert by["global_daily"].limit == 1000 and by["global_monthly"].limit == 10000
    assert by["per_ip_daily"].resets_at.isoformat() == "2027-01-01T00:00:00+00:00"
    assert by["global_monthly"].resets_at.isoformat() == "2027-01-01T00:00:00+00:00"
    assert {c.quota for c in counters_for(None, s, now)} == {"global_daily", "global_monthly"}


async def test_memory_store_is_all_or_nothing(monkeypatch):
    s = _settings(monkeypatch, llm_quota_per_ip_per_day=2, llm_quota_global_per_day=3)
    store = MemoryQuotaStore()
    now = datetime(2026, 11, 7, 12, tzinfo=UTC)
    assert await store.consume(counters_for("a", s, now)) is None
    assert await store.consume(counters_for("a", s, now)) is None
    denied = await store.consume(counters_for("a", s, now))
    assert denied is not None and denied.quota == "per_ip_daily" and denied.limit == 2
    assert denied.resets_at == "2026-11-08T00:00:00Z"
    # The refused call charged nothing, so the global day still has one unit.
    assert await store.consume(counters_for("b", s, now)) is None
    g = await store.consume(counters_for("c", s, now))
    assert g is not None and g.quota == "global_daily"


class _Inner:
    def __init__(self) -> None:
        self.calls = 0

    async def ainvoke(self, prompt: str) -> Any:
        self.calls += 1
        return type("R", (), {"content": "REAL"})()


class _Mock:
    async def ainvoke(self, prompt: str) -> Any:
        return type("R", (), {"content": "MOCK"})()


async def test_guard_falls_back_to_mock_visibly(monkeypatch):
    _settings(monkeypatch, llm_quota_per_ip_per_day=1)
    events: asyncio.Queue[StepEvent] = asyncio.Queue()
    ctx = RunQuotaContext(run_id="r1", events=events, client_ip="203.0.113.1")
    token = current_run.set(ctx)
    try:
        inner = _Inner()
        llm = QuotaGuardedLLM(inner, _Mock())
        assert (await llm.ainvoke("p")).content == "REAL"
        assert (await llm.ainvoke("p")).content == "MOCK"
        assert (await llm.ainvoke("p")).content == "MOCK"
        assert inner.calls == 1
    finally:
        current_run.reset(token)
    ev = events.get_nowait()
    assert ev.type == "llm.quota_exceeded"
    dumped = ev.model_dump()
    assert dumped["quota"] == "per_ip_daily" and dumped["limit"] == 1
    assert dumped["resets_at"].endswith("Z") and dumped["llm_quota_exceeded"] is True
    assert events.empty()  # one event per run, not per refused call
    assert ctx.summary() == {
        "llm_quota_exceeded": True,
        "llm_quota": {"quota": "per_ip_daily", "limit": 1, "resets_at": dumped["resets_at"]},
        "llm_calls_on_mock": 2,
    }


async def test_store_failure_fails_closed(monkeypatch):
    _settings(monkeypatch)

    class Broken:
        async def consume(self, counters):
            raise ConnectionError("db down")

        async def aclose(self):
            return None

    monkeypatch.setattr(quota_mod, "_store", Broken())
    denial = await check_llm_quota()
    assert denial == QuotaDenial("quota_store_unavailable", None, None)


def test_mock_provider_is_not_counted(monkeypatch):
    _settings(monkeypatch, llm_provider="mock")
    from playground.agents.base import _MockLLM, llm_for_settings

    assert isinstance(llm_for_settings(), _MockLLM)


async def test_run_result_and_events_carry_the_quota_hit(monkeypatch):
    _settings(monkeypatch, llm_provider="openai", llm_quota_per_ip_per_day=1)
    from playground.agents import base as agents_base

    monkeypatch.setattr(agents_base, "build_llm", lambda *a, **k: _Inner())

    async def scenario_run(spec: RunSpec, events: Any) -> RunResult:
        llm = agents_base.llm_for_settings()
        first = await llm.ainvoke("one")
        second = await llm.ainvoke("two")
        return RunResult(
            run_id=spec.run_id,
            scenario_id=spec.scenario_id,
            summary={"answers": [first.content, second.content]},
        )

    scenario = ScenarioDef(id="quota_probe", name="q", description="q", run=scenario_run)
    spec = RunSpec(run_id="run-q", scenario_id="quota_probe")
    events: asyncio.Queue[StepEvent] = asyncio.Queue()
    result = await execute(scenario, spec, events, client_ip="203.0.113.5")

    assert result.status == "complete"
    assert result.summary["answers"][0] == "REAL"
    assert result.summary["answers"][1].startswith("MOCK_LLM_RESPONSE")
    assert result.summary["llm_quota_exceeded"] is True
    assert result.summary["llm_quota"]["quota"] == "per_ip_daily"
    seen = []
    while not events.empty():
        seen.append(events.get_nowait().model_dump())
    types = [e["type"] for e in seen]
    assert types == ["run.started", "llm.quota_exceeded", "run.complete"]
    assert seen[-1]["llm_quota_exceeded"] is True
    assert seen[-1]["llm_quota"]["resets_at"] == seen[1]["resets_at"]
    assert current_run.get() is None  # the run context does not leak


async def test_global_quota_applies_without_a_client_ip(monkeypatch):
    _settings(monkeypatch, llm_quota_global_per_day=1)
    ctx = RunQuotaContext(run_id="r", events=None, client_ip=None)
    token = current_run.set(ctx)
    try:
        assert await check_llm_quota() is None
        denial = await check_llm_quota()
    finally:
        current_run.reset(token)
    assert denial is not None and denial.quota == "global_daily"


# ── registry passthrough ────────────────────────────────────────────────────


@pytest.fixture
def upstream(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.host == "down.invalid":
            raise httpx.ConnectError("refused", request=req)
        return httpx.Response(
            200,
            json={"path": req.url.path},
            headers={"etag": '"v1"', "set-cookie": "s=1", "x-internal": "1"},
        )

    monkeypatch.setenv("REGISTRY_A_URL", "http://registry-a.railway.internal:8100")
    monkeypatch.setenv("REGISTRY_B_URL", "http://registry-b.railway.internal:8200/")
    get_settings.cache_clear()
    monkeypatch.setattr(
        registry_proxy, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    yield seen
    monkeypatch.setattr(registry_proxy, "_client", None)


@pytest.mark.parametrize(
    ("registry", "path"),
    [
        ("a", "healthz"),
        ("a", "contexts/search"),
        ("b", "lineages/lin:sha256:abc"),
        ("b", "lineages/lin:sha256:abc/current"),
        ("a", ".well-known/acdp.json"),
        ("a", ".well-known/jwks.json"),
        ("b", ".well-known/did.json"),
    ],
)
def test_passthrough_forwards_allow_listed_reads(upstream, registry, path):
    with TestClient(app) as c:
        r = c.get(f"/registries/{registry}/{path}", headers={"x-api-key": "k", "accept": "a/b"})
    assert r.status_code == 200
    assert r.headers["etag"] == '"v1"'
    assert "set-cookie" not in r.headers and "x-internal" not in r.headers
    (req,) = upstream
    assert req.url.host == f"registry-{registry}.railway.internal"
    assert req.url.path == f"/{path}"
    assert req.headers["accept"] == "a/b"
    assert "x-api-key" not in req.headers


def test_passthrough_forwards_the_query_string(upstream):
    with TestClient(app) as c:
        r = c.get("/registries/a/contexts/search?q=cash&tag=a&tag=b&cursor=x%2Fy")
    assert r.status_code == 200
    assert upstream[0].url.query == b"q=cash&tag=a&tag=b&cursor=x%2Fy"


@pytest.mark.parametrize(
    "path",
    [
        "contexts/abc",  # retrieval is not in the console's registry allowlist
        "contexts",
        "lineages/a/b",
        "lineages/x/current/extra",
        "lineages/..%2Fadmin",
        "lineages/%2E%2E/current",
        ".well-known/other.json",
        "admin/keys",
        "healthz/",
    ],
)
def test_passthrough_rejects_everything_else(upstream, path):
    with TestClient(app) as c:
        assert c.get(f"/registries/a/{path}").status_code == 404
    assert upstream == []


def test_passthrough_is_get_only_and_registry_bounded(upstream):
    with TestClient(app) as c:
        assert c.post("/registries/a/contexts/search").status_code == 405
        assert c.get("/registries/c/healthz").status_code == 422
    assert upstream == []


def test_passthrough_reports_an_unreachable_registry(upstream, monkeypatch):
    monkeypatch.setenv("REGISTRY_A_URL", "http://down.invalid")
    get_settings.cache_clear()
    with TestClient(app) as c:
        r = c.get("/registries/a/healthz")
    assert r.status_code == 502
    assert r.json()["detail"]["code"] == "registry_unreachable"


def test_passthrough_is_behind_the_gate(upstream, monkeypatch):
    _enforced(monkeypatch)
    with TestClient(app) as c:
        assert c.get("/registries/a/healthz").status_code == 401
        assert c.get("/registries/a/healthz", headers={"x-api-key": KEY}).status_code == 200
    assert len(upstream) == 1


async def test_postgres_store_closes_pool_when_schema_setup_fails(monkeypatch):
    """A failed schema step must not leak the pool, and the call fails (closed)."""
    import asyncpg

    from playground.quota import PostgresQuotaStore

    closed: list[bool] = []
    seen: dict = {}

    class _Conn:
        async def execute(self, *a):
            raise RuntimeError("schema failed")

    class _Acq:
        async def __aenter__(self):
            return _Conn()

        async def __aexit__(self, *a):
            return False

    class _Pool:
        def acquire(self):
            return _Acq()

        async def close(self):
            closed.append(True)

    async def fake_create_pool(dsn, **kw):
        seen.update(kw)
        return _Pool()

    monkeypatch.setattr(asyncpg, "create_pool", fake_create_pool)
    store = PostgresQuotaStore("postgresql://unused")
    with pytest.raises(RuntimeError):
        await store.consume([])
    assert closed == [True]
    assert store._pool is None
    assert seen["timeout"] <= 10


def test_enforcement_without_a_webhook_secret_refuses_to_start(monkeypatch):
    """The webhook route skips the key gate on the strength of its HMAC; no secret, no start."""
    monkeypatch.setenv("PLAYGROUND_REQUIRE_API_KEY", "true")
    monkeypatch.setenv("PLAYGROUND_API_KEY", KEY)
    monkeypatch.setenv("WEBHOOK_SECRET", "")
    get_settings.cache_clear()
    with pytest.raises(ValidationError, match="WEBHOOK_SECRET is empty"):
        get_settings()


@pytest.mark.parametrize(
    ("raw", "bucket"),
    [
        ("203.0.113.9", "203.0.113.9"),
        ("::ffff:203.0.113.9", "203.0.113.9"),
        ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
        ("203.0.113.9, 10.0.0.1", None),
        ("garbage", None),
    ],
)
def test_client_ip_buckets_normalise(raw, bucket):
    from playground.security import _parse_ip

    assert _parse_ip(raw) == bucket


async def test_wedged_quota_store_refuses_the_call_after_a_deadline(monkeypatch):
    """A store that never answers must not hold the run: the call is refused, fail closed."""
    from playground.quota import check_llm_quota

    class _Wedged:
        async def consume(self, counters):
            await asyncio.Event().wait()

        async def aclose(self):
            return None

    monkeypatch.setattr(quota_mod, "_store", _Wedged())
    monkeypatch.setattr(quota_mod, "QUOTA_CHECK_TIMEOUT_S", 0.05)
    denial = await check_llm_quota()
    assert denial is not None and denial.quota == "quota_store_unavailable"


async def test_run_past_its_deadline_errors_and_frees_the_run(monkeypatch):
    from playground.scenarios.runner import execute

    _settings(monkeypatch, run_timeout_seconds="0.05")

    async def _hang(spec, events):
        await asyncio.Event().wait()

    scenario = ScenarioDef(id="hang", name="hang", description="", run=_hang)
    events: asyncio.Queue = asyncio.Queue()
    result = await execute(scenario, RunSpec(run_id="r-hang", scenario_id="hang"), events)
    assert result.status == "failed"
    assert "RUN_TIMEOUT_SECONDS" in (result.error or "")
