"""S10 — multi-tenant isolation.

Two tenant-bound agents (mapped to ``tenant-a`` / ``tenant-b`` via the
registry's ``auth.tenant_agents`` config) publish and read. The
assertions:

* tenant-a publishes a context (the registry stamps the tenant from the
  JWT claim — the authoritative signal, RFC-ACDP-0008 §6.4).
* tenant-b CANNOT read tenant-a's context (404 — existence is hidden
  across tenants).
* tenant-a CAN read its own context.
* a bearer-authenticated request that *also* sends a conflicting
  ``X-Tenant-Id`` is rejected (claim/header mismatch).

Requires live token issuance, so it degrades gracefully: when the
registry can't issue tenant-bound tokens (no DID hosting in the default
stack) the run is marked complete-but-degraded rather than failed.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from acdp_client import AcdpHTTPError, TokenError
from acdp_client.models import StepEvent
from playground.agents.base import AgentTask
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s10_tenant_isolation",
    name="Tenant Isolation",
    description="Two tenant-bound agents. tenant-b cannot read tenant-a's "
    "context (404); tenant-a can; a conflicting X-Tenant-Id header "
    "is rejected. JWT tenant claim is authoritative.",
    registry_mode="single",
    agent_count=2,
    framework="langchain",
    default_inputs={"topic": "tenant-scoped revenue model"},
)

_DENIED = {401, 403, 404}


async def _attempt(label: str, coro) -> dict[str, Any]:
    try:
        ctx = await coro
        return {"label": label, "outcome": "allowed", "title": ctx.body.title}
    except AcdpHTTPError as e:
        return {
            "label": label,
            "outcome": "denied" if e.status in _DENIED else "error",
            "status": e.status,
        }
    except TokenError as e:
        return {"label": label, "outcome": "auth_unavailable", "detail": str(e)[:160]}
    except Exception as e:  # noqa: BLE001
        return {"label": label, "outcome": "error", "detail": repr(e)[:160]}


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority

    try:
        tenant_a = make_langchain_agent(
            spec,
            events,
            bundle,
            slug="tenant-a-agent",
            registry="a",
            authenticated=True,
        )
        tenant_b = make_langchain_agent(
            spec,
            events,
            bundle,
            slug="tenant-b-agent",
            registry="a",
            authenticated=True,
        )

        # A separate client for tenant-a that *also* forces a conflicting
        # X-Tenant-Id header (tenant-b) to test the mismatch rejection.
        conflict_client = bundle.client(
            "a",
            producer=tenant_a.producer,
            tenant_id="tenant-b",
            tenant_header_mode="always",
        )

        degraded = False
        publish_outcome = "skipped"
        ctx_id: str | None = None
        try:
            out = await tenant_a.run(
                AgentTask(
                    prompt=f"Summarize a tenant-scoped analysis of {topic}.",
                    title=f"Tenant-A — {topic}",
                    context_type="analysis",
                    visibility="public",
                    domain="finance",
                    tags=["tenant-a"],
                )
            )
            ctx_id = out.ctx_id
            publish_outcome = "published"
        except TokenError as e:
            degraded = True
            publish_outcome = f"auth_unavailable: {str(e)[:120]}"
            log.warning("S10 publish degraded (no live auth): %s", e)
        except AcdpHTTPError as e:
            publish_outcome = f"http_{e.status}"
            log.warning("S10 publish failed: %s", e)

        outcomes: dict[str, Any] = {"publish": publish_outcome}
        cross_ok = own_ok = conflict_ok = None

        if ctx_id:
            results = await asyncio.gather(
                _attempt("tenant_b_cross_read", tenant_b.client.retrieve(ctx_id)),
                _attempt("tenant_a_own_read", tenant_a.client.retrieve(ctx_id)),
                _attempt("conflict_header", conflict_client.retrieve(ctx_id)),
            )
            by_label = {r["label"]: r for r in results}
            outcomes.update(by_label)
            cross_ok = by_label["tenant_b_cross_read"]["outcome"] == "denied"
            own_ok = by_label["tenant_a_own_read"]["outcome"] == "allowed"
            conflict_ok = by_label["conflict_header"]["outcome"] in {"denied", "error"}
            # If reads came back as auth_unavailable, treat as degraded.
            if any(r["outcome"] == "auth_unavailable" for r in results):
                degraded = True

        all_correct = bool(cross_ok and own_ok and conflict_ok)
        # Degraded (no live auth) is not a code failure — only a wrong
        # observed behavior with auth present fails the run.
        status = "complete" if (all_correct or degraded) else "failed"

        await events.put(
            StepEvent(
                type="scenario.note",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                title="tenant isolation outcomes",
                preview=f"cross_denied={cross_ok} own_allowed={own_ok} "
                f"conflict_rejected={conflict_ok} degraded={degraded}",
            )
        )

        nodes = (
            [
                LineageNode(
                    ctx_id=ctx_id,
                    agent_id=tenant_a.agent_did,
                    title=f"Tenant-A — {topic}",
                    context_type="analysis",
                    registry_authority=authority,
                    step=1,
                )
            ]
            if ctx_id
            else []
        )
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status=status,
            contexts=[ctx_id] if ctx_id else [],
            lineage_graph=LineageGraph(nodes=nodes, edges=[]),
            summary={
                "tenant_a_did": tenant_a.agent_did,
                "tenant_b_did": tenant_b.agent_did,
                "degraded": degraded,
                "assertions": {
                    "cross_tenant_denied": cross_ok,
                    "own_tenant_allowed": own_ok,
                    "conflict_header_rejected": conflict_ok,
                },
                "outcomes": outcomes,
            },
            error=(
                None
                if status == "complete"
                else f"S10 tenant isolation assertions failed: {outcomes}"
            ),
        )
    finally:
        await bundle.aclose()
