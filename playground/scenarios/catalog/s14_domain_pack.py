"""S14 — domain-pack context-type gating.

With a domain pack registered (e.g. ``finance`` via ``DOMAIN_PACKS``),
the control plane:

* lists the active pack at ``GET /domain-packs``, and
* gates webhook ingest by context type — base ACDP types and
  pack-declared types are accepted; an unknown type is rejected (400).

We list the packs and exercise the ingest gate by HMAC-signing two
synthetic events (one accepted base type, one unknown type). Requires a
control plane; degrades gracefully otherwise.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from acdp_client.models import StepEvent

from playground.config import get_settings
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s14_domain_pack",
    name="Domain-Pack Gating",
    description="Lists active domain packs and exercises the ingest context-type "
    "gate: a base type is accepted, an unknown pack-gated type is "
    "rejected (400).",
    registry_mode="single",
    agent_count=0,
    framework="langchain",
    default_inputs={},
)


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _event(ctx_type: str) -> bytes:
    payload = {
        "type": "context_published",
        "ctx_id": "acdp://registry-a.playground.local/s14-probe",
        "agent_id": "did:web:registry-a.playground.local:agents:probe",
        "context_type": ctx_type,
        "visibility": "public",
        "version": 1,
        "derived_from": [],
        "registry_authority": "registry-a.playground.local",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return json.dumps(payload).encode()


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
    secret = settings.control_plane_hmac_secret
    summary: dict[str, Any] = {"degraded": False}

    async with httpx.AsyncClient(timeout=10.0) as http:
        # 1) List active packs.
        try:
            r = await http.get(f"{base}/domain-packs")
            packs = r.json().get("packs", []) if r.is_success else []
            summary["packs"] = [p.get("id") for p in packs]
        except httpx.HTTPError as e:
            summary["degraded"] = True
            summary["error"] = str(e)[:160]
            return RunResult(
                run_id=spec.run_id,
                scenario_id=SCENARIO.id,
                status="complete",
                summary=summary,
            )

        # 2) Ingest gate: base type accepted, unknown type rejected.
        async def ingest(ctx_type: str) -> int | str:
            body = _event(ctx_type)
            headers = {"Content-Type": "application/json"}
            if secret:
                headers["X-ACDP-Signature"] = _sign(secret, body)
            try:
                resp = await http.post(f"{base}/ingest/acdp", content=body, headers=headers)
                return resp.status_code
            except httpx.HTTPError as e:
                return f"error:{e}"

        base_status = await ingest("data_snapshot")
        unknown_status = await ingest("zzz_unknown_pack_type")

    summary["base_type_status"] = base_status
    summary["unknown_type_status"] = unknown_status

    # Base type accepted (2xx); unknown type rejected (400). If packs
    # aren't actually gating (no packs registered), unknown may be 2xx —
    # treat that as degraded rather than a hard failure.
    base_ok = isinstance(base_status, int) and 200 <= base_status < 300
    unknown_rejected = unknown_status == 400
    gating_active = bool(summary.get("packs"))
    ok = base_ok and (unknown_rejected or not gating_active)
    if gating_active and not unknown_rejected:
        summary["note"] = "packs registered but unknown type not rejected"

    await events.put(
        StepEvent(
            type="scenario.note",
            run_id=spec.run_id,
            ts=datetime.now(timezone.utc).isoformat(),
            title="domain-pack gating",
            preview=f"packs={summary.get('packs')} base={base_status} unknown={unknown_status}",
        )
    )

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if ok else "failed",
        summary=summary,
        error=None if ok else f"S14 domain-pack gating unexpected: {summary}",
    )
