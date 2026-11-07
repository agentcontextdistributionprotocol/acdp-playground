"""LLM-call quotas, counted per real LLM call.

Four counters gate every call to a real model: per client IP per UTC day
and per UTC month, and global per UTC day and per UTC month. Limits come
from settings (``LLM_QUOTA_PER_IP_PER_DAY`` and friends). A call consumes one
unit from each applicable counter, and it is all or nothing: if any counter
would go past its limit, none is charged and the call is refused.

A refused call does not fail the run. :class:`QuotaGuardedLLM` answers it
with the deterministic mock instead, emits an ``llm.quota_exceeded`` event
naming the quota and its reset time, and records the denial on the run so
the runner marks ``RunResult.summary`` (``llm_quota_exceeded``). Nothing
falls back silently.

Counters live in Postgres when ``DATABASE_URL`` is set, so they survive
redeploys, and in process memory otherwise (local development, tests). If
the store errors, the call is refused (fail closed, reported as
``quota_store_unavailable``) rather than spending without a count.

The run's client IP reaches the guard through :data:`current_run`, a
context variable the runner sets for the scenario task, so no scenario code
has to thread it through.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Protocol

from acdp_client.models import StepEvent
from playground.config import Settings, get_settings

log = logging.getLogger(__name__)

GLOBAL_SUBJECT = "*"


@dataclass(frozen=True)
class QuotaDenial:
    quota: str  # per_ip_daily | per_ip_monthly | global_daily | global_monthly | quota_store_unavailable
    limit: int | None
    resets_at: str | None  # RFC 3339, UTC

    def as_dict(self) -> dict[str, Any]:
        return {"quota": self.quota, "limit": self.limit, "resets_at": self.resets_at}


@dataclass(frozen=True)
class _Counter:
    quota: str
    scope: str  # stored key: ip_day | ip_month | global_day | global_month
    subject: str
    window_start: date
    limit: int
    resets_at: datetime


def _next_month(d: date) -> date:
    return date(d.year + (d.month == 12), d.month % 12 + 1, 1)


def counters_for(ip: str | None, settings: Settings, now: datetime) -> list[_Counter]:
    """The counters one call charges, in a fixed order (Postgres locks rows in it)."""
    today = now.astimezone(UTC).date()
    month = today.replace(day=1)
    day_reset = datetime.combine(today + timedelta(days=1), time(), UTC)
    month_reset = datetime.combine(_next_month(month), time(), UTC)
    out = [
        _Counter(
            "global_daily",
            "global_day",
            GLOBAL_SUBJECT,
            today,
            settings.llm_quota_global_per_day,
            day_reset,
        ),
        _Counter(
            "global_monthly",
            "global_month",
            GLOBAL_SUBJECT,
            month,
            settings.llm_quota_global_per_month,
            month_reset,
        ),
    ]
    if ip is not None:
        out += [
            _Counter(
                "per_ip_daily", "ip_day", ip, today, settings.llm_quota_per_ip_per_day, day_reset
            ),
            _Counter(
                "per_ip_monthly",
                "ip_month",
                ip,
                month,
                settings.llm_quota_per_ip_per_month,
                month_reset,
            ),
        ]
    return out


def _deny(c: _Counter) -> QuotaDenial:
    return QuotaDenial(c.quota, c.limit, c.resets_at.isoformat().replace("+00:00", "Z"))


class QuotaStore(Protocol):
    async def consume(self, counters: list[_Counter]) -> QuotaDenial | None: ...

    async def aclose(self) -> None: ...


class MemoryQuotaStore:
    """In-process counters. Lost on restart; for local development and tests."""

    def __init__(self) -> None:
        self._counts: dict[tuple[str, str, date], int] = {}
        self._lock = asyncio.Lock()

    async def consume(self, counters: list[_Counter]) -> QuotaDenial | None:
        async with self._lock:
            for c in counters:
                if self._counts.get((c.scope, c.subject, c.window_start), 0) >= c.limit:
                    return _deny(c)
            for c in counters:
                key = (c.scope, c.subject, c.window_start)
                self._counts[key] = self._counts.get(key, 0) + 1
            return None

    async def aclose(self) -> None:
        return None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS playground_llm_usage (
    scope        text    NOT NULL,
    subject      text    NOT NULL,
    window_start date    NOT NULL,
    calls        integer NOT NULL,
    PRIMARY KEY (scope, subject, window_start)
)
"""
_UPSERT = """
INSERT INTO playground_llm_usage (scope, subject, window_start, calls)
VALUES ($1, $2, $3, 1)
ON CONFLICT (scope, subject, window_start)
DO UPDATE SET calls = playground_llm_usage.calls + 1
RETURNING calls
"""
# Monthly rows need to outlive the month they count; anything older is dead.
_PRUNE = "DELETE FROM playground_llm_usage WHERE window_start < $1"
_CONNECT_TIMEOUT_S = 5.0
QUOTA_CHECK_TIMEOUT_S = 10.0


class _OverLimit(Exception):
    def __init__(self, counter: _Counter):
        self.counter = counter


class PostgresQuotaStore:
    """Durable counters in one table; each call is one transaction.

    Every counter is upserted (+1, row-locked) in the fixed order from
    :func:`counters_for`, so concurrent calls serialise per row without
    deadlocking. If any count passes its limit the transaction rolls back,
    which un-charges the counters already bumped.
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: Any = None
        self._init_lock = asyncio.Lock()

    async def _get_pool(self) -> Any:
        if self._pool is None:
            async with self._init_lock:
                if self._pool is None:
                    import asyncpg

                    # A short connect timeout: an unreachable database refuses
                    # the call (fail closed) in seconds, not asyncpg's default 60.
                    pool = await asyncpg.create_pool(
                        self._dsn, min_size=1, max_size=5, timeout=_CONNECT_TIMEOUT_S
                    )
                    try:
                        async with pool.acquire() as conn:
                            await conn.execute(_SCHEMA)
                            cutoff = datetime.now(UTC).date().replace(day=1) - timedelta(days=62)
                            await conn.execute(_PRUNE, cutoff)
                    except BaseException:
                        await pool.close()
                        raise
                    self._pool = pool
        return self._pool

    async def consume(self, counters: list[_Counter]) -> QuotaDenial | None:
        pool = await self._get_pool()
        try:
            async with pool.acquire() as conn, conn.transaction():
                for c in counters:
                    calls = await conn.fetchval(_UPSERT, c.scope, c.subject, c.window_start)
                    if calls > c.limit:
                        raise _OverLimit(c)
        except _OverLimit as e:
            return _deny(e.counter)
        return None

    async def aclose(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None


_store: QuotaStore | None = None


def get_quota_store() -> QuotaStore:
    global _store
    if _store is None:
        dsn = get_settings().database_url
        if dsn:
            _store = PostgresQuotaStore(dsn)
        else:
            log.warning(
                "DATABASE_URL is not set: LLM quotas are counted in memory and reset on restart"
            )
            _store = MemoryQuotaStore()
    return _store


async def reset_quota_store() -> None:
    """Close and forget the store (shutdown, tests)."""
    global _store
    if _store is not None:
        await _store.aclose()
    _store = None


# ── per-run context ─────────────────────────────────────────────────────────


@dataclass
class RunQuotaContext:
    run_id: str
    events: asyncio.Queue[StepEvent] | None
    # The IP charged for per-IP quotas, or None when per-IP limits don't
    # apply to this run (see playground/security.py).
    client_ip: str | None
    denials: list[QuotaDenial] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        if not self.denials:
            return {}
        first = self.denials[0]
        return {
            "llm_quota_exceeded": True,
            "llm_quota": first.as_dict(),
            "llm_calls_on_mock": len(self.denials),
        }


current_run: contextvars.ContextVar[RunQuotaContext | None] = contextvars.ContextVar(
    "playground_run_quota", default=None
)


async def check_llm_quota() -> QuotaDenial | None:
    """Charge one real LLM call to the current run's counters; a denial if refused."""
    ctx = current_run.get()
    counters = counters_for(ctx.client_ip if ctx else None, get_settings(), datetime.now(UTC))
    try:
        # A deadline, so a wedged database connection refuses the call
        # instead of holding the run (and its concurrency slot) forever.
        denial = await asyncio.wait_for(get_quota_store().consume(counters), QUOTA_CHECK_TIMEOUT_S)
    except Exception:
        log.exception("LLM quota store failed; refusing the call (fail closed)")
        denial = QuotaDenial("quota_store_unavailable", None, None)
    if denial is not None and ctx is not None:
        first = not ctx.denials
        ctx.denials.append(denial)
        if first and ctx.events is not None:
            await ctx.events.put(
                StepEvent(
                    type="llm.quota_exceeded",
                    run_id=ctx.run_id,
                    ts=datetime.now(UTC).isoformat(),
                    error=f"LLM quota exceeded ({denial.quota}); this run continues on the mock LLM",
                    llm_quota_exceeded=True,
                    quota=denial.quota,
                    limit=denial.limit,
                    resets_at=denial.resets_at,
                )
            )
    return denial


class QuotaGuardedLLM:
    """Wraps a real chat model: charge the quota first, or answer with the mock."""

    def __init__(self, inner: Any, fallback: Any) -> None:
        self.inner = inner
        self.fallback = fallback

    async def ainvoke(self, prompt: Any, *args: Any, **kwargs: Any) -> Any:
        if await check_llm_quota() is not None:
            return await self.fallback.ainvoke(prompt)
        return await self.inner.ainvoke(prompt, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)
