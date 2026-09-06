"""S20 — reserved-tenant assertion is rejected (cross-boundary defense).

``default`` is the silent column default for untenanted rows. If a caller
could *assert* it — via the ``X-Tenant-Id`` header or a signed ``tenant``
claim — the request would alias the entire untenanted bucket, a
cross-boundary read/write. Both siblings now refuse it:

* registry — ``reject_reserved_tenant`` (acdp-registry-core ``c988ea4`` /
  ``#24``), surfaced as a 400 ``schema_violation`` on publish/retrieve.
* control plane — ``AuthGuard.assertNotReservedTenant`` (acdp-control-plane
  ``#50``), a 403 ``not_authorized`` on any tenant-scoped route.

Untenanted access stays reachable **only** through the *absence* of an
assertion — never by asserting ``default``.

The playground mirrors the rule client-side (``acdp_client.identifiers
.reject_reserved_tenant``, wired into :class:`acdp_client.AcdpClient` and
the control-plane bridge) so a caller fails fast locally with a clear
message instead of a confusing server rejection. This scenario exercises
that guard **fully offline** — no registry, network, or LLM required. The
hard server-contract assertion (400 / 403 against a mock transport) lives
in ``tests/test_reserved_tenant.py``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

import httpx

from acdp_client import RESERVED_TENANT, AcdpClient, reject_reserved_tenant
from acdp_client.models import StepEvent
from playground.control_plane import _tenant_header
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s20_reserved_tenant",
    name="Reserved-tenant rejection",
    description="Asserting the reserved 'default' tenant (via X-Tenant-Id or a "
    "token claim) is refused — it would alias the untenanted bucket. "
    "Registry 400 schema_violation / CP 403 not_authorized; mirrored "
    "client-side. Runs fully offline.",
    registry_mode="single",
    agent_count=0,
    framework="langchain",
    default_inputs={},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    outcomes: dict[str, str] = {}

    async def note(title: str, preview: str) -> None:
        await events.put(
            StepEvent(
                type="scenario.note",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                title=title,
                preview=preview,
            )
        )

    # 1. The standalone guard rejects the reserved sentinel...
    try:
        reject_reserved_tenant(RESERVED_TENANT)
        outcomes["guard"] = "NOT-BLOCKED"
    except ValueError:
        outcomes["guard"] = "blocked"
    await note("reserved sentinel", outcomes["guard"])

    # 2. ...and passes through the absence of an assertion (untenanted access).
    try:
        reject_reserved_tenant(None)
        outcomes["untenanted"] = "allowed"
    except ValueError:  # pragma: no cover - must never happen
        outcomes["untenanted"] = "WRONGLY-BLOCKED"
    await note("untenanted (no assertion)", outcomes["untenanted"])

    # 3. A real tenant assertion is still honoured.
    try:
        reject_reserved_tenant("tenant-a")
        outcomes["real_tenant"] = "allowed"
    except ValueError:  # pragma: no cover
        outcomes["real_tenant"] = "WRONGLY-BLOCKED"
    await note("real tenant", outcomes["real_tenant"])

    # 4. AcdpClient fails fast at construction if tenant_id == "default".
    try:
        AcdpClient(
            "http://reg.invalid",
            http=httpx.AsyncClient(),
            tenant_id=RESERVED_TENANT,
        )
        outcomes["client_ctor"] = "NOT-BLOCKED"
    except ValueError:
        outcomes["client_ctor"] = "blocked"
    await note("AcdpClient(tenant_id='default')", outcomes["client_ctor"])

    # 5. The control-plane bridge refuses to stamp X-Tenant-Id: default.
    try:
        _tenant_header(RESERVED_TENANT)
        outcomes["cp_bridge"] = "NOT-BLOCKED"
    except ValueError:
        outcomes["cp_bridge"] = "blocked"
    await note("CP bridge X-Tenant-Id", outcomes["cp_bridge"])

    ok = (
        outcomes["guard"] == "blocked"
        and outcomes["untenanted"] == "allowed"
        and outcomes["real_tenant"] == "allowed"
        and outcomes["client_ctor"] == "blocked"
        and outcomes["cp_bridge"] == "blocked"
    )

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if ok else "failed",
        contexts=[],
        summary={
            "reserved_tenant_guard": outcomes,
            # The live wire contract (registry 400 schema_violation / CP 403
            # not_authorized) is asserted against a mock transport in
            # tests/test_reserved_tenant.py.
            "server_contract": "registry 400 schema_violation / CP 403 not_authorized",
        },
        error=None if ok else "S20 reserved-tenant guard assertions failed",
    )
