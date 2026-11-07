"""PostgresQuotaStore against a real Postgres.

Skipped unless ``PLAYGROUND_TEST_DATABASE_URL`` points at a disposable
database (CI provides a service container; locally, for example,
``docker run -d -p 55432:5432 -e POSTGRES_PASSWORD=pg postgres:17`` and
``PLAYGROUND_TEST_DATABASE_URL=postgresql://postgres:pg@localhost:55432/postgres``).
The test drops and recreates the ``playground_llm_usage`` table.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

import pytest

from playground.config import Settings
from playground.quota import PostgresQuotaStore, counters_for

DSN = os.environ.get("PLAYGROUND_TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DSN, reason="PLAYGROUND_TEST_DATABASE_URL not set")

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)


@pytest.fixture
async def store():
    import asyncpg

    conn = await asyncpg.connect(DSN)
    await conn.execute("DROP TABLE IF EXISTS playground_llm_usage")
    await conn.close()
    s = PostgresQuotaStore(DSN)
    yield s
    await s.aclose()


def _settings(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


async def test_concurrent_calls_never_exceed_the_limit(store):
    s = _settings(llm_quota_per_ip_per_day=30, llm_quota_global_per_day=1000)
    results = await asyncio.gather(
        *(store.consume(counters_for("198.51.100.1", s, NOW)) for _ in range(50))
    )
    allowed = [r for r in results if r is None]
    denied = [r for r in results if r is not None]
    assert len(allowed) == 30
    assert {d.quota for d in denied} == {"per_ip_daily"}


async def test_refused_call_rolls_back_every_counter(store):
    s = _settings(llm_quota_per_ip_per_day=1, llm_quota_global_per_day=2)
    assert await store.consume(counters_for("a", s, NOW)) is None
    assert (await store.consume(counters_for("a", s, NOW))).quota == "per_ip_daily"
    # The refused call bumped then rolled back the global counter: one unit is left.
    assert await store.consume(counters_for("b", s, NOW)) is None
    assert (await store.consume(counters_for("c", s, NOW))).quota == "global_daily"


async def test_counts_survive_a_new_store(store):
    s = _settings(llm_quota_per_ip_per_day=2)
    assert await store.consume(counters_for("a", s, NOW)) is None
    await store.aclose()
    again = PostgresQuotaStore(DSN)
    try:
        assert await again.consume(counters_for("a", s, NOW)) is None
        denied = await again.consume(counters_for("a", s, NOW))
        assert denied is not None and denied.resets_at == "2026-11-08T00:00:00Z"
    finally:
        await again.aclose()


async def test_new_day_and_month_get_fresh_windows(store):
    s = _settings(llm_quota_per_ip_per_day=1, llm_quota_per_ip_per_month=2)
    assert await store.consume(counters_for("a", s, NOW)) is None
    tomorrow = datetime(2026, 11, 8, 0, 0, 1, tzinfo=UTC)
    assert await store.consume(counters_for("a", s, tomorrow)) is None
    denied = await store.consume(counters_for("a", s, datetime(2026, 11, 9, tzinfo=UTC)))
    assert denied is not None and denied.quota == "per_ip_monthly"
    assert denied.resets_at == "2026-12-01T00:00:00Z"
    assert await store.consume(counters_for("a", s, datetime(2026, 12, 1, tzinfo=UTC))) is None
