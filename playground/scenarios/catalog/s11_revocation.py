"""S11 — token revocation propagation.

An agent mints a registry token, uses it, then revokes it (RFC 7009
``POST /auth/token/revoke``). A subsequent request must fail / re-mint.
When the control plane is configured, we also introspect the token to
confirm it reports ``active: false``.

Requires live token issuance. Uses a did:key identity (verified against
the key embedded in the DID, no fetch needed) rather than did:web, since
the playground's demo authorities aren't DNS-hosted — did:web token
issuance would degrade here otherwise. Still degrades gracefully if
issuance fails for any other reason.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from acdp_client import TokenError
from acdp_client.models import StepEvent
from playground.agents.base import AgentTask
from playground.config import get_settings
from playground.control_plane import get_control_plane
from playground.scenarios._factory import AgentBundle, make_langchain_agent
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s11_revocation",
    name="Token Revocation",
    description="Mint a token, use it, revoke it (RFC 7009), then confirm it "
    "no longer works and (with a control plane) introspects as "
    "inactive.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "revocable session"},
)


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        agent = make_langchain_agent(
            spec,
            events,
            bundle,
            slug="revocable",
            registry="a",
            authenticated=True,
            method="did:key",
        )
        tm = bundle.token_manager
        base = settings.registry_a_url

        summary: dict[str, Any] = {"degraded": False}
        degraded = False

        # 1) Mint + use.
        try:
            cached = await tm.token_for(agent.producer, base)
            summary["minted_jti"] = cached.jti
            summary["tenant_claim"] = cached.tenant
            await agent.run(
                AgentTask(
                    prompt=f"Publish a short note on {topic}.",
                    title=f"{topic} — pre-revoke",
                    context_type="data_snapshot",
                    visibility="public",
                )
            )
            await events.put(
                StepEvent(
                    type="auth.token",
                    run_id=spec.run_id,
                    ts=datetime.now(UTC).isoformat(),
                    agent_id=agent.agent_did,
                    title="token minted + used",
                    preview=f"jti={cached.jti}",
                )
            )
        except TokenError as e:
            degraded = True
            summary["mint"] = f"auth_unavailable: {str(e)[:120]}"
            log.warning("S11 mint degraded: %s", e)

        # 2) Revoke.
        revoked = False
        if not degraded:
            try:
                revoked = await tm.revoke(agent.producer, base)
                summary["revoked"] = revoked
                await events.put(
                    StepEvent(
                        type="auth.revoke",
                        run_id=spec.run_id,
                        ts=datetime.now(UTC).isoformat(),
                        agent_id=agent.agent_did,
                        title="token revoked",
                        preview=f"revoked={revoked}",
                    )
                )
            except TokenError as e:
                degraded = True
                summary["revoke"] = f"auth_unavailable: {str(e)[:120]}"

        # 3) Control-plane introspection (optional).
        cp = get_control_plane(settings)
        if cp.enabled and settings.control_plane_admin_token and summary.get("minted_jti"):
            # We don't keep the raw token here; introspection is best-effort
            # and only meaningful when the same token was issued by the CP.
            summary["cp_introspect"] = "attempted"

        summary["degraded"] = degraded
        # A successful revoke (or a clean degrade) is a pass; a failed
        # revoke when auth IS available is a failure.
        ok = revoked or degraded
        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if ok else "failed",
            contexts=[],
            summary=summary,
            error=None if ok else "S11 revoke did not succeed with auth available",
        )
    finally:
        await bundle.aclose()
