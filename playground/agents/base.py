"""Base playground agent: owns an ACDP identity, emits SSE step events.

Subclasses override :meth:`call_llm` (or :meth:`run` for full control).
The crypto path is fixed: build the publish request via the SDK, then
POST it via :class:`AcdpClient`. The HTTP client returns a
``PublishResponse`` with ``ctx_id`` / ``lineage_id``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from acdp_client import AcdpClient, FullContext, PublishResponse
from acdp_client.models import StepEvent
from acdp_client.signing import Producer

log = logging.getLogger(__name__)


class AgentTask(BaseModel):
    """One unit of work for an agent.

    The agent will run :meth:`call_llm` (or use ``override_response``)
    and publish the result to the registry.
    """

    prompt: str
    title: str
    context_type: str = "data_snapshot"
    visibility: str = "public"
    domain: str | None = None
    tags: list[str] = Field(default_factory=list)
    derived_from: list[str] = Field(default_factory=list)
    audience: list[str] = Field(default_factory=list)
    contributors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None
    # ── extended body fields (acdp-py feature-parity, 2026-05) ──
    # `data_refs` is a list of acdp-data-ref objects; `data_period` is a
    # {"start","end"} RFC-3339 window; `expires_at` is an RFC-3339 stamp.
    data_refs: list[dict[str, Any]] = Field(default_factory=list)
    data_period: dict[str, str] | None = None
    expires_at: str | None = None
    schema_uri: str | None = None
    idempotency_key: str | None = None  # optional Idempotency-Key on publish
    summary_chars: int = 500
    override_response: str | None = None  # bypass the LLM (used in tests/mocks)


class AgentOutput(BaseModel):
    ctx_id: str
    lineage_id: str
    version: int
    title: str
    llm_response: str
    content_hash: str


class BasePlaygroundAgent:
    """An agent that owns one :class:`AcdpProducer` and one :class:`AcdpClient`."""

    framework: str = "base"

    def __init__(
        self,
        producer: Producer,
        client: AcdpClient,
        events: asyncio.Queue[StepEvent],
        run_id: str,
        *,
        authority_map: dict[str, AcdpClient] | None = None,
        slug: str | None = None,
    ):
        self.producer = producer
        self.client = client
        self.events = events
        self.run_id = run_id
        self.authority_map = authority_map or {}
        self.slug = slug

    # ── identity helpers ────────────────────────────────────────────────

    @property
    def agent_did(self) -> str:
        return self.producer.agent_did

    # ── event emission ───────────────────────────────────────────────────

    async def _emit(self, event_type: str, **fields: Any) -> None:
        ev = StepEvent(
            type=event_type,  # type: ignore[arg-type]
            run_id=self.run_id,
            ts=datetime.now(UTC).isoformat(),
            agent_id=self.agent_did,
            framework=self.framework,
            **fields,
        )
        await self.events.put(ev)

    # ── ACDP operations ─────────────────────────────────────────────────

    def _publish_kwargs(self, task: AgentTask, llm_result: str) -> dict[str, Any]:
        """Build the SDK ``build_publish_request`` kwargs from a task.

        Optional fields are JSON-encoded strings where the SDK expects
        them (``metadata``, ``data_refs``, ``data_period``); omitted
        entirely when empty so the producer-content preimage (and thus
        the content hash) stays minimal and stable.
        """
        metadata: dict[str, Any] = {
            "agent_framework": self.framework,
            "run_id": self.run_id,
            **(task.metadata or {}),
        }
        if self.slug:
            metadata["agent_slug"] = self.slug

        kwargs: dict[str, Any] = {
            "title": task.title,
            "context_type": task.context_type,
            "visibility": task.visibility,
            "summary": llm_result[: task.summary_chars],
            "domain": task.domain,
            "tags": task.tags or None,
            "derived_from": task.derived_from or None,
            "audience": task.audience or None,
            "contributors": task.contributors or None,
            "schema_uri": task.schema_uri,
            "metadata": json.dumps(metadata),
        }
        if task.data_refs:
            kwargs["data_refs"] = json.dumps(task.data_refs)
        if task.data_period:
            kwargs["data_period"] = json.dumps(task.data_period)
        if task.expires_at:
            kwargs["expires_at"] = task.expires_at
        return kwargs

    async def publish(self, task: AgentTask, llm_result: str) -> AgentOutput:
        req_json = self.producer.build_publish_request(**self._publish_kwargs(task, llm_result))
        resp: PublishResponse = await self.client.publish(
            req_json, idempotency_key=task.idempotency_key
        )
        req = json.loads(req_json)
        out = AgentOutput(
            ctx_id=resp.ctx_id,
            lineage_id=resp.lineage_id,
            version=resp.version,
            title=task.title,
            llm_response=llm_result,
            content_hash=req["content_hash"],
        )
        await self._emit(
            "acdp.publish",
            ctx_id=out.ctx_id,
            title=task.title,
            derived_from=task.derived_from,
            preview=llm_result[:100],
        )
        return out

    async def supersede(
        self,
        previous_body_json: str,
        task: AgentTask,
        llm_result: str,
        *,
        expected_lineage_id: str | None = None,
    ) -> AgentOutput:
        """Publish a new version that supersedes ``previous_body_json``.

        Uses the SDK's ``build_supersede_request`` so the lineage id is
        carried forward and the version auto-incremented. When
        ``expected_lineage_id`` is supplied it is sent as a concurrency
        guard (``lin:sha256:<hex>``); the registry rejects it on a v1
        body and honours it from v2 onward.
        """
        metadata: dict[str, Any] = {
            "agent_framework": self.framework,
            "run_id": self.run_id,
            **(task.metadata or {}),
        }
        if self.slug:
            metadata["agent_slug"] = self.slug

        kwargs: dict[str, Any] = {
            "previous_body_json": previous_body_json,
            "title": task.title,
            "summary": llm_result[: task.summary_chars],
            "tags": task.tags or None,
            "domain": task.domain,
            "metadata": json.dumps(metadata),
        }
        if task.data_refs:
            kwargs["data_refs"] = json.dumps(task.data_refs)
        if task.data_period:
            kwargs["data_period"] = json.dumps(task.data_period)
        if task.expires_at:
            kwargs["expires_at"] = task.expires_at
        if expected_lineage_id is not None:
            kwargs["expected_lineage_id"] = expected_lineage_id

        req_json = self.producer.build_supersede_request(**kwargs)
        resp: PublishResponse = await self.client.publish(req_json)
        req = json.loads(req_json)
        out = AgentOutput(
            ctx_id=resp.ctx_id,
            lineage_id=resp.lineage_id,
            version=resp.version,
            title=task.title,
            llm_response=llm_result,
            content_hash=req["content_hash"],
        )
        await self._emit(
            "acdp.publish",
            ctx_id=out.ctx_id,
            title=task.title,
            derived_from=task.derived_from,
            preview=llm_result[:100],
        )
        return out

    async def retrieve(self, ctx_id: str) -> FullContext:
        ctx = await self.client.resolve(ctx_id, self.authority_map)
        await self._emit("acdp.retrieve", ctx_id=ctx_id)
        return ctx

    async def search(self, **filters: Any) -> Any:
        results = await self.client.search(**filters)
        await self._emit("acdp.search", title=str(filters))
        return results

    # ── LLM hook ─────────────────────────────────────────────────────────

    async def call_llm(self, prompt: str) -> str:
        """Subclasses override. Default raises."""
        raise NotImplementedError

    # ── default run() ───────────────────────────────────────────────────

    async def run(self, task: AgentTask) -> AgentOutput:
        await self._emit("agent.started", title=task.title)

        # Optionally ground in fetched contexts
        grounding = ""
        for ctx_id in task.derived_from[:2]:
            ctx = await self.retrieve(ctx_id)
            who = ctx.body.agent_id.split(":")[-1]
            grounding += f"\n\n[ground: {who} — {ctx.body.title}]\n{ctx.body.summary or ''}"

        prompt = task.prompt
        if grounding:
            prompt = f"{task.prompt}\n\nUse this grounding material:{grounding}"

        if task.override_response is not None:
            llm_result = task.override_response
        else:
            await self._emit("llm.thinking", preview=prompt[:100])
            llm_result = await self.call_llm(prompt)

        return await self.publish(task, llm_result)


# ── LLM factory ──────────────────────────────────────────────────────────


def build_llm(provider: str, model: str, *, api_key: str = "") -> Any:
    """Return a langchain chat model (or a deterministic mock).

    Imported lazily so the playground can run scenarios with
    ``provider='mock'`` without LangChain/OpenAI installed.
    """
    if provider == "mock":
        return _MockLLM()
    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(model=model, api_key=api_key or None)
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model=model, api_key=api_key or None)
    raise ValueError(f"unknown LLM provider: {provider}")


class _MockLLM:
    """Deterministic offline LLM used in smoke tests."""

    async def ainvoke(self, prompt: str) -> Any:  # mimics langchain's ainvoke signature
        snippet = prompt.strip().splitlines()[0][:80]
        text = (
            "MOCK_LLM_RESPONSE :: "
            f"echoing first line: {snippet} :: "
            "this would be an LLM-generated answer in production."
        )
        return type("Resp", (), {"content": text})()
