"""The producer agent: an a2a-sdk A2A server whose completed artifacts are ACDP
bodies it signs itself (RFC-ACDP-0022, profile ``acdp-producer-a2a``).

The agent does one small real task. It reads the sensor-reading datasets that
the client cites in ``Message.metadata["io.acdp/inputs"]``, then returns a
summary artifact: a text part plus a data part with the statistics.

Every RFC-0022 step on the agent side runs in acdp-rs's ``acdp-a2a``, through
``acdp-a2a-sidecar``:

- assembling the two chunks;
- the salted ``acdp-a2a-artifact/1`` record;
- the did:key signature;
- publishing before the completing chunk is emitted;
- the ``Idempotency-Key`` and the ``io.acdp/provenance`` link;
- failing open;
- the ``https://acdp.io/ext/a2a/v1`` Card entry.

This module adds three things:

- the A2A plumbing (a2a-sdk proto ↔ A2A JSON);
- verifying cited inputs before they count (§7 step 3), with the ``acdp``
  wheel;
- a demo-only retraction route (RFC-ACDP-0013), which signs with the same
  key through the ``acdp`` wheel.
"""

from __future__ import annotations

import json
import logging
import statistics
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from a2a.helpers import (
    get_message_text,
    new_data_part,
    new_task_from_user_message,
    new_text_message,
    new_text_part,
)
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentInterface,
    AgentSkill,
    Artifact,
    TaskArtifactUpdateEvent,
    TaskState,
)
from acdp import AcdpProducer, AcdpVerifier
from acdp_client import AcdpClient
from google.protobuf.json_format import MessageToDict, ParseDict
from playground.scenarios._receipts import mint_lifecycle_event
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from acdp_a2a_demo.sidecar import Sidecar

log = logging.getLogger("acdp_a2a_demo.producer")

A2A_PROTOCOL_VERSION = "1.0"
BODY_TYPE = "analysis"
ARTIFACT_NAME = "Sensor summary"


@dataclass(frozen=True)
class ProducerSettings:
    seed: bytes
    registry_url: str
    registry: str
    public_url: str
    # Local demo stack only: plain http on loopback (see README "Local relaxations").
    allow_local_http: bool = True
    # §13.3 recommends private; the demo registry serves only public bodies
    # to anonymous holders, so the demo publishes public throwaway bodies.
    visibility: str = "public"


@dataclass
class _Input:
    ctx_id: str
    station: str
    unit: str
    readings: list[float] = field(default_factory=list)


def to_json(message: Any) -> dict[str, Any]:
    """A proto message in A2A JSON (ProtoJSON, camelCase), the form RFC-0022 hashes."""
    return MessageToDict(message)


def _embedded_dataset(body: dict[str, Any]) -> dict[str, Any] | None:
    for ref in body.get("data_refs") or []:
        embedded = ref.get("embedded") or {}
        content = embedded.get("content")
        if embedded.get("encoding") == "json" and isinstance(content, dict):
            return content
    return None


def analyse(inputs: list[_Input], question: str) -> tuple[str, dict[str, Any]]:
    """The agent's task: summarize the cited readings."""
    readings = [r for i in inputs for r in i.readings]
    if not readings:
        return ("No verified readings were cited, so there is nothing to summarize.", {})
    unit = inputs[0].unit
    # Drift per station (second half against first half), then averaged.
    drifts = [
        statistics.fmean(i.readings[len(i.readings) // 2 :])
        - statistics.fmean(i.readings[: max(len(i.readings) // 2, 1)])
        for i in inputs
        if i.readings
    ]
    drift = statistics.fmean(drifts)
    trend = "rising" if drift > 0.05 else "falling" if drift < -0.05 else "flat"
    stats = {
        "stations": [i.station for i in inputs],
        "count": len(readings),
        "mean": round(statistics.fmean(readings), 3),
        "min": min(readings),
        "max": max(readings),
        "trend": trend,
        "unit": unit,
    }
    text = (
        f"{question.strip() or 'Summary'}: {stats['count']} readings from "
        f"{', '.join(stats['stations'])}; mean {stats['mean']} {unit} "
        f"(min {stats['min']}, max {stats['max']}), trend {trend}."
    )
    return text, stats


class SensorAnalystExecutor(AgentExecutor):
    """Summarizes cited datasets; every completed artifact goes through acdp-a2a."""

    def __init__(self, sidecar: Sidecar, registry: AcdpClient, settings: ProducerSettings):
        self._sidecar = sidecar
        self._registry = registry
        self._settings = settings

    async def _verify_inputs(self, cited: list[str]) -> list[_Input]:
        """§7 step 3: retrieve each cited input and verify it (RFC-ACDP-0001 §5.11).

        Only the demo registry is allowlisted, and an input that cannot be
        retrieved or verified is left out. The registry's own did:web is not
        web-hosted on the local stack, so acdp-rs's ``CrossRegistryResolver``
        (which requires that binding) cannot run here. The body check itself
        is the ``acdp`` wheel's ``verify_body_offline`` for a did:key producer.
        """
        out: list[_Input] = []
        for ctx_id in cited:
            authority = ctx_id.removeprefix("acdp://").split("/", 1)[0]
            if authority != self._settings.registry:
                log.info("input %s: authority not allowlisted, ignored", ctx_id)
                continue
            try:
                raw = await self._registry.retrieve_raw(ctx_id)
                body = raw["body"]
                AcdpVerifier.verify_body_offline(json.dumps(body))
            except Exception as exc:  # noqa: BLE001 - any failure drops the input
                log.info("input %s: not verified (%s), ignored", ctx_id, exc)
                continue
            dataset = _embedded_dataset(body) or {}
            readings = [float(x) for x in dataset.get("readings", [])]
            out.append(
                _Input(
                    ctx_id=ctx_id,
                    station=str(dataset.get("station", body.get("title", "?"))),
                    unit=str(dataset.get("unit", "")),
                    readings=readings,
                )
            )
        return out

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        assert context.message is not None
        task = context.current_task
        if task is None:
            task = new_task_from_user_message(context.message)
            await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue=event_queue, task_id=task.id, context_id=task.context_id)
        sc = self._sidecar
        await sc.call("begin", task_id=task.id, context_id=task.context_id)
        try:
            # §7: io.acdp/inputs → cited, in message order.
            noted = await sc.call("message", task_id=task.id, message=to_json(context.message))
            await updater.update_status(
                state=TaskState.TASK_STATE_WORKING,
                message=new_text_message("Verifying cited inputs", task_id=task.id),
            )
            inputs = await self._verify_inputs(noted["cited"])
            await sc.call("verified_inputs", task_id=task.id, ids=[i.ctx_id for i in inputs])

            text, stats = analyse(inputs, get_message_text(context.message))
            artifact_id = f"summary-{uuid.uuid4()}"
            chunks = [
                TaskArtifactUpdateEvent(
                    task_id=task.id,
                    context_id=task.context_id,
                    artifact=Artifact(
                        artifact_id=artifact_id,
                        name=ARTIFACT_NAME,
                        parts=[new_text_part(text, media_type="text/plain")],
                    ),
                    append=False,
                    last_chunk=False,
                ),
                TaskArtifactUpdateEvent(
                    task_id=task.id,
                    context_id=task.context_id,
                    artifact=Artifact(
                        artifact_id=artifact_id,
                        parts=[new_data_part(stats, media_type="application/json")],
                    ),
                    append=True,
                    last_chunk=True,
                ),
            ]
            for chunk in chunks:
                # The sidecar returns the chunk to emit; on the completing
                # chunk the body is already published and the link attached.
                out = await sc.call("chunk", task_id=task.id, chunk=to_json(chunk))
                if "withhold" in out:  # fail-closed (not this demo's default)
                    await updater.failed(
                        message=new_text_message("Provenance publishing failed", task_id=task.id)
                    )
                    return
                await event_queue.enqueue_event(ParseDict(out["emit"], TaskArtifactUpdateEvent()))
            await updater.complete()
        finally:
            await sc.call("end", task_id=task.id)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("cancel is not supported")


def agent_card(settings: ProducerSettings, card_extension: dict[str, Any]) -> AgentCard:
    return AgentCard(
        name="ACDP Sensor Analyst",
        description="Summarizes cited sensor datasets. Every completed artifact is "
        "published as a signed ACDP body (RFC-ACDP-0022).",
        version="0.1.0",
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain", "application/json"],
        capabilities=AgentCapabilities(
            streaming=True,
            # §9: exactly one entry, required false, params {registry, agentId},
            # built by acdp-a2a's card::card_extension.
            extensions=[ParseDict(card_extension, AgentExtension())],
        ),
        supported_interfaces=[
            AgentInterface(
                protocol_binding="JSONRPC",
                url=settings.public_url,
                protocol_version=A2A_PROTOCOL_VERSION,
            )
        ],
        skills=[
            AgentSkill(
                id="summarize-readings",
                name="Summarize readings",
                description="Summarize the sensor datasets cited in io.acdp/inputs.",
                tags=["acdp", "a2a", "provenance"],
                examples=["Summarize the cited readings"],
            )
        ],
    )


def _now_ms() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


async def create_app(settings: ProducerSettings) -> tuple[Starlette, dict[str, Any]]:
    """Start the sidecar, build the Card, and return the A2A app plus identity."""
    sidecar = await Sidecar.start()
    ident = await sidecar.call(
        "init",
        seed_hex=settings.seed.hex(),
        registry_url=settings.registry_url,
        registry=settings.registry,
        a2a_protocol_version=A2A_PROTOCOL_VERSION,
        body_type=BODY_TYPE,
        visibility=settings.visibility,
        domain="sensors.demo",
        tags=["a2a", "rfc-0022"],
        allow_local_http=settings.allow_local_http,
    )
    # The retraction route signs with the same key through the acdp wheel.
    signer = AcdpProducer.from_seed_did_key(settings.seed)
    if signer.agent_did != ident["agent_id"]:
        raise RuntimeError(
            f"seed maps to {signer.agent_did} in Python, {ident['agent_id']} in Rust"
        )
    registry = AcdpClient(settings.registry_url)
    card = agent_card(settings, ident["card_extension"])
    handler = DefaultRequestHandler(
        agent_executor=SensorAnalystExecutor(sidecar, registry, settings),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )

    async def retract(request: Request) -> JSONResponse:
        """Demo-only: the agent withdraws one of its own bodies (RFC-ACDP-0013).

        This is the agent acting on its own output through the registry. It
        is not a push into tasks or clients: holders find out only when they
        re-check (RFC-0022 §8 step 6, §11).
        """
        payload = await request.json()
        ctx_id = str(payload["ctx_id"])
        raw = await registry.retrieve_raw(ctx_id)
        if raw["body"]["agent_id"] != signer.agent_did:
            return JSONResponse({"error": "not this agent's body"}, status_code=403)
        event = mint_lifecycle_event(
            signer,
            event_id=str(uuid.uuid4()),
            ctx_id=ctx_id,
            event_type="retracted",
            occurred_at=_now_ms(),
            reason=str(payload.get("reason") or "withdrawn by the producing agent"),
        )
        after = await registry.retract(ctx_id, json.dumps(event))
        status = after.registry_state.status if after.registry_state else None
        return JSONResponse({"ctx_id": ctx_id, "status": status, "event_id": event["event_id"]})

    routes = [
        *create_agent_card_routes(card),
        *create_jsonrpc_routes(handler, "/"),
        Route("/demo/retract", retract, methods=["POST"]),
    ]

    @asynccontextmanager
    async def lifespan(_app: Starlette):  # type: ignore[no-untyped-def]
        try:
            yield
        finally:
            await sidecar.close()
            await registry.aclose()

    return Starlette(routes=routes, lifespan=lifespan), ident
