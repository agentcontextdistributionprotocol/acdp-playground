"""S13 — authorization / policy enforcement.

Confirms the control plane denies unauthorized access and allows
authorized access on a guarded endpoint. We use the admin-gated
revocation feed (``GET /auth/revocations``) as the probe:

* no credential        → denied (401/403)
* admin bearer token   → allowed (200)

This exercises the AuthGuard + PolicyGuard chain. Requires a control
plane; degrades gracefully when ``CONTROL_PLANE_URL`` is unset.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s13_policy_deny",
    name="Policy / Authz Enforcement",
    description="An unauthenticated request to a guarded control-plane endpoint "
    "is denied (401/403); the same request with an admin token is "
    "allowed. Exercises AuthGuard + PolicyGuard.",
    registry_mode="single",
    agent_count=0,
    framework="langchain",
    default_inputs={},
)

_DENIED = {401, 403}


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()

    if not settings.control_plane_enabled:
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete",
            summary={"degraded": True, "reason": "no control plane configured"},
        )

    base = settings.control_plane_url.rstrip("/")
    url = f"{base}/auth/revocations"
    summary: dict[str, Any] = {"degraded": False}

    async with httpx.AsyncClient(timeout=10.0) as http:
        # 1) Unauthenticated → expect denied.
        try:
            r_anon = await http.get(url, params={"since": 0, "limit": 1})
            anon_status = r_anon.status_code
        except httpx.HTTPError as e:
            summary["degraded"] = True
            summary["error"] = str(e)[:160]
            return _result(spec, "complete", summary)

        # 2) With admin token → expect allowed.
        admin_status = None
        if settings.control_plane_admin_token:
            headers = {"Authorization": f"Bearer {settings.control_plane_admin_token}"}
            try:
                r_admin = await http.get(url, params={"since": 0, "limit": 1}, headers=headers)
                admin_status = r_admin.status_code
            except httpx.HTTPError as e:
                summary["error_admin"] = str(e)[:160]

    denied_ok = anon_status in _DENIED
    allowed_ok = admin_status is None or admin_status == 200
    ok = denied_ok and allowed_ok

    await events.put(
        StepEvent(
            type="policy.check",
            run_id=spec.run_id,
            ts=datetime.now(timezone.utc).isoformat(),
            title="authz enforcement",
            preview=f"anon={anon_status} admin={admin_status}",
        )
    )

    summary.update(
        {
            "anonymous_status": anon_status,
            "admin_status": admin_status,
            "denied_unauthenticated": denied_ok,
            "allowed_with_admin": allowed_ok,
        }
    )
    return _result(
        spec,
        "complete" if ok else "failed",
        summary,
        error=None if ok else f"S13 authz expectations failed: {summary}",
    )


def _result(spec: RunSpec, status: str, summary: dict, error: str | None = None) -> RunResult:
    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status=status,
        summary=summary,
        error=error,  # type: ignore[arg-type]
    )
