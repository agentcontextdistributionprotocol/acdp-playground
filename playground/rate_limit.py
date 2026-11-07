"""Run-launch limits for ``POST /runs``.

Two in-process limits sit on top of the LLM quotas:

- per client IP, at most ``RUN_RATE_LIMIT_PER_IP`` launches in any sliding
  ``RUN_RATE_LIMIT_WINDOW_SECONDS`` window (default 5 per 600 s);
- at most ``MAX_CONCURRENT_RUNS`` runs in flight at once (default 3).

Both answer ``429`` with ``Retry-After``. They are deliberately in memory:
the windows are minutes long and the service runs one replica, so losing
them on a redeploy costs nothing, unlike the daily/monthly LLM quotas, which
are in Postgres. Per-IP limiting is skipped when the request carries no IP
to charge (see ``per_ip_limits`` in :mod:`playground.security`).
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass

from playground.config import get_settings

# A concurrency slot frees when some run finishes; there is no exact time to
# promise, so ask the client to come back shortly.
CONCURRENCY_RETRY_AFTER_SECONDS = 10


@dataclass
class RunLimitExceeded(Exception):
    code: str  # run_rate_limited | max_concurrent_runs
    limit: int
    retry_after: int
    message: str


class RunLimiter:
    def __init__(self) -> None:
        self._launches: dict[str, deque[float]] = {}
        self.active = 0

    def acquire(self, client_ip: str | None, now: float | None = None) -> None:
        """Reserve a run slot or raise :class:`RunLimitExceeded`.

        Check and reserve happen without an ``await`` between them, so two
        concurrent requests on the event loop cannot both take the last slot.
        """
        s = get_settings()
        now = time.monotonic() if now is None else now
        if self.active >= s.max_concurrent_runs:
            raise RunLimitExceeded(
                "max_concurrent_runs",
                s.max_concurrent_runs,
                CONCURRENCY_RETRY_AFTER_SECONDS,
                f"{self.active} runs already in flight (limit {s.max_concurrent_runs})",
            )
        if client_ip is not None:
            window = s.run_rate_limit_window_seconds
            launches = self._launches.setdefault(client_ip, deque())
            while launches and launches[0] <= now - window:
                launches.popleft()
            if len(launches) >= s.run_rate_limit_per_ip:
                retry = max(1, math.ceil(launches[0] + window - now))
                raise RunLimitExceeded(
                    "run_rate_limited",
                    s.run_rate_limit_per_ip,
                    retry,
                    f"at most {s.run_rate_limit_per_ip} runs per {window} s per client",
                )
            launches.append(now)
            self._prune(now - window)
        self.active += 1

    def release(self) -> None:
        self.active = max(0, self.active - 1)

    def _prune(self, cutoff: float) -> None:
        # Drop IPs whose every launch has aged out, so the map stays bounded.
        if len(self._launches) < 1024:
            return
        for ip in [ip for ip, q in self._launches.items() if not q or q[-1] <= cutoff]:
            del self._launches[ip]


run_limiter = RunLimiter()
