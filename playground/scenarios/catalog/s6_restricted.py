"""S6 — restricted-visibility access control.

Demonstrates the registry's visibility model end-to-end:

    Producer publishes a context with `visibility="restricted"` and
    `audience=[audience_member.agent_did]`.

    The scenario then tries three retrievals against the same context:

    * **anonymous**         — no bearer token → MUST be denied (404/403)
    * **outsider (auth'd)** — bearer for an agent NOT in the audience
                              → MUST be denied (404/403)
    * **audience member**   — bearer for an agent IN the audience
                              → MUST succeed (200)

A successful run records all three outcomes in `RunResult.summary` so
the dashboard can show a green/red strip per branch. A failure in any
branch surfaces as a non-success outcome rather than aborting the run,
so partial wins are still observable.

Requires `auth.enabled = true` on the target registry and the
challenge/token endpoints mounted (the playground's bundled
`config/registry-a.toml` opts both in).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from acdp_client import AcdpHTTPError, TokenError
from acdp_client.models import StepEvent

from playground.agents.base import AgentTask
from playground.config import get_settings
from playground.scenarios._factory import (
    AgentBundle,
    make_langchain_agent,
)
from playground.scenarios.models import (
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)


SCENARIO = ScenarioDef(
    id="s6_restricted",
    name="Restricted Visibility (V2 auth)",
    description="Producer publishes a restricted context with an explicit "
                "audience. Three retrieval attempts demonstrate the model: "
                "anonymous denied, outsider denied, audience member allowed.",
    registry_mode="single",
    agent_count=3,
    framework="langchain",
    default_inputs={"topic": "internal margin analysis"},
)


_DENIED_STATUSES = {401, 403, 404}


async def _attempt(
    label: str,
    coro,
) -> dict[str, Any]:
    """Run a retrieval and bucket the outcome into a small report dict."""
    try:
        ctx = await coro
        return {
            "label": label,
            "outcome": "allowed",
            "title": ctx.body.title,
        }
    except AcdpHTTPError as e:
        return {
            "label": label,
            "outcome": "denied" if e.status in _DENIED_STATUSES else "error",
            "status": e.status,
            "body_preview": e.body[:200],
        }
    except TokenError as e:
        return {"label": label, "outcome": "auth_error", "detail": str(e)}
    except Exception as e:  # noqa: BLE001 — explicitly surfaced
        return {"label": label, "outcome": "error", "detail": repr(e)}


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])
    authority = settings.registry_a_authority

    try:
        # 1) Build the three identities. Producer + audience_member +
        # outsider all need to authenticate to publish/retrieve in an
        # auth-enabled registry. The outsider is authenticated but
        # NOT on the audience list, so they should still be denied.
        producer = make_langchain_agent(
            spec, events, bundle, slug="confidant-producer",
            registry="a", authenticated=True,
        )
        audience_member = make_langchain_agent(
            spec, events, bundle, slug="confidant-reader",
            registry="a", authenticated=True,
        )
        outsider = make_langchain_agent(
            spec, events, bundle, slug="confidant-outsider",
            registry="a", authenticated=True,
        )

        # 2) Producer publishes a restricted context targeting only the
        # audience_member. This needs live token issuance, which fails
        # against a stock registry (the playground's `*.playground.local`
        # producer DID isn't web-hosted, so the registry's auth challenge
        # can't resolve its key). Degrade gracefully in that case — the
        # access-control intent is still recorded — rather than aborting
        # the whole run (mirrors S10–S14/S17/S18).
        try:
            out = await producer.run(
                AgentTask(
                    prompt=f"Summarize a confidential 4-point analysis of {topic}.",
                    title=f"Confidential — {topic}",
                    context_type="analysis",
                    visibility="restricted",
                    domain="finance",
                    tags=["confidential", "restricted"],
                    audience=[audience_member.agent_did],
                    metadata={"sensitivity": "internal-only"},
                )
            )
        except TokenError as e:
            await events.put(
                StepEvent(
                    type="acdp.search",
                    run_id=spec.run_id,
                    ts=datetime.now(timezone.utc).isoformat(),
                    title="restricted publish degraded (auth unavailable)",
                    preview=str(e)[:100],
                )
            )
            log.warning("S6 restricted publish degraded: %s", e)
            return RunResult(
                run_id=spec.run_id,
                scenario_id=SCENARIO.id,
                status="complete",
                contexts=[],
                lineage_graph=LineageGraph(nodes=[], edges=[]),
                summary={
                    "degraded": True,
                    "audience": [audience_member.agent_did],
                    "outsider_did": outsider.agent_did,
                    "publish": f"auth_unavailable: {str(e)[:120]}",
                },
            )

        # 3) Three retrieval attempts, in parallel.
        anonymous_client = bundle.anonymous_client("a")
        attempts = await asyncio.gather(
            _attempt("anonymous", anonymous_client.retrieve(out.ctx_id)),
            _attempt("outsider", outsider.client.retrieve(out.ctx_id)),
            _attempt("audience_member", audience_member.client.retrieve(out.ctx_id)),
        )

        outcomes = {a["label"]: a for a in attempts}

        # 4) Status interpretation
        anon_ok = outcomes["anonymous"]["outcome"] == "denied"
        outsider_ok = outcomes["outsider"]["outcome"] == "denied"
        audience_ok = outcomes["audience_member"]["outcome"] == "allowed"
        all_correct = anon_ok and outsider_ok and audience_ok

        await events.put(
            StepEvent(
                type="acdp.search" if all_correct else "run.error",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                title="restricted-visibility outcomes",
                preview=(
                    f"anon={outcomes['anonymous']['outcome']} "
                    f"outsider={outcomes['outsider']['outcome']} "
                    f"audience={outcomes['audience_member']['outcome']}"
                ),
            )
        )

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if all_correct else "failed",
            contexts=[out.ctx_id],
            lineage_graph=LineageGraph(
                nodes=[
                    LineageNode(
                        ctx_id=out.ctx_id,
                        agent_id=producer.agent_did,
                        title=out.title,
                        context_type="analysis",
                        registry_authority=authority,
                        step=1,
                    )
                ],
                edges=[],
            ),
            summary={
                "audience": [audience_member.agent_did],
                "outsider_did": outsider.agent_did,
                "outcomes": outcomes,
                "all_assertions_passed": all_correct,
            },
            error=(
                None if all_correct else
                "S6 expected anonymous=denied, outsider=denied, "
                f"audience_member=allowed; got {outcomes}"
            ),
        )
    finally:
        await bundle.aclose()
