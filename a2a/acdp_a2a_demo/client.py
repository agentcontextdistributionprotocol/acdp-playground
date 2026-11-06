"""The client agent: calls the producer over A2A and verifies what it gets back
as a holder (RFC-ACDP-0022 §8, profile ``acdp-consumer-a2a``).

Verification is acdp-verifier-py's independent RFC-0022 holder,
``acdp_verifier.a2a``:

- :func:`verify_artifact` runs steps 1–5 over the retrieved body;
- :func:`artifact_status` runs step 6.

This module adds only the host-language pieces:

- the A2A calls (a2a-sdk);
- the Agent Card fetch;
- publishing the client's own input dataset;
- retrieving bodies from an allowlisted registry over httpx;
- packaging the retrieval's lifecycle events as an ``acdp-evidence/1``
  bundle, so the holder can read retraction (RFC-ACDP-0013).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.helpers import new_text_part
from a2a.types import AgentCard, GetTaskRequest, Message, Role, SendMessageRequest, Task, TaskState
from acdp import AcdpCanonicalizer, AcdpProducer
from acdp_client import AcdpClient
from acdp_verifier.a2a import (
    ArtifactMismatch,
    ArtifactStatus,
    ArtifactVerification,
    artifact_status,
    card_pointer,
    verify_artifact,
)
from acdp_verifier.errors import AcdpError
from google.protobuf.json_format import MessageToDict, ParseDict

LINK_KEY = "io.acdp/provenance"
INPUTS_KEY = "io.acdp/inputs"
TERMINAL = {
    TaskState.TASK_STATE_COMPLETED,
    TaskState.TASK_STATE_FAILED,
    TaskState.TASK_STATE_CANCELED,
    TaskState.TASK_STATE_REJECTED,
}


def _now_ms() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ctx_authority(ctx_id: str) -> str:
    return ctx_id.removeprefix("acdp://").split("/", 1)[0]


# ── Inputs ──────────────────────────────────────────────────────────────────


async def publish_dataset(
    registry: AcdpClient, owner: AcdpProducer, station: str, readings: list[float]
) -> str:
    """The client publishes its own input under its own did:key; returns ``ctx_id``."""
    content = {"station": station, "unit": "celsius", "readings": readings}
    canonical = AcdpCanonicalizer.canonicalize(json.dumps(content))
    refs = [
        {
            "type": "primary_result",
            "format": "json",
            "embedded": {"encoding": "json", "content": content},
            "content_hash": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
        }
    ]
    request = owner.build_publish_request(
        title=f"{station} readings",
        context_type="data_snapshot",
        visibility="public",
        domain="sensors.demo",
        tags=["a2a-demo-input"],
        data_refs=json.dumps(refs),
    )
    return (await registry.publish(request)).ctx_id


# ── The A2A call ────────────────────────────────────────────────────────────


@dataclass
class Exchange:
    card: AgentCard
    task: Task

    @property
    def card_extensions(self) -> list[dict[str, Any]]:
        return MessageToDict(self.card).get("capabilities", {}).get("extensions", [])

    @property
    def artifacts(self) -> list[dict[str, Any]]:
        """The final Task's artifacts in A2A JSON: where a holder reads the link (§4.2, §6)."""
        return MessageToDict(self.task).get("artifacts", [])


class _RewritingTransport(httpx.AsyncBaseTransport):
    """An on-path attacker between client and agent: it rewrites JSON responses."""

    def __init__(self, inner: httpx.AsyncBaseTransport, rewrite: Callable[[Any], bool]):
        self._inner = inner
        self._rewrite = rewrite
        self.rewrites = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        if request.method != "POST":
            return response
        raw = await response.aread()
        try:
            doc = json.loads(raw)
        except ValueError:
            return httpx.Response(response.status_code, headers=response.headers, content=raw)
        if self._rewrite(doc):
            self.rewrites += 1
            raw = json.dumps(doc).encode()
        headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
        return httpx.Response(response.status_code, headers=headers, content=raw)

    async def aclose(self) -> None:
        await self._inner.aclose()


def tamper_first_text_part(doc: Any) -> bool:
    """Change one Part in transit: the first text part of the first artifact seen."""
    if isinstance(doc, dict):
        for artifact in doc.get("artifacts") or []:
            for part in artifact.get("parts") or []:
                if isinstance(part.get("text"), str):
                    part["text"] = part["text"].replace("mean", "mean (adjusted)", 1) + " [edited]"
                    return True
        return any(tamper_first_text_part(v) for v in doc.values())
    if isinstance(doc, list):
        return any(tamper_first_text_part(v) for v in doc)
    return False


async def call_agent(
    agent_url: str,
    text: str,
    inputs: list[str],
    *,
    tamper: bool = False,
    timeout: float = 60.0,
) -> Exchange:
    """Send one message citing ``inputs`` (§7) and return the Card and the final Task."""
    transport: httpx.AsyncBaseTransport = httpx.AsyncHTTPTransport()
    if tamper:
        transport = _RewritingTransport(transport, tamper_first_text_part)
    async with httpx.AsyncClient(transport=transport, timeout=timeout) as http:
        card = await A2ACardResolver(http, agent_url).get_agent_card()
        client = await create_client(card, ClientConfig(streaming=False, httpx_client=http))
        message = Message(
            role=Role.ROLE_USER,
            message_id=str(uuid.uuid4()),
            parts=[new_text_part(text)],
        )
        if inputs:
            ParseDict({INPUTS_KEY: inputs}, message.metadata)
        task: Task | None = None
        async for response in client.send_message(SendMessageRequest(message=message)):
            if response.HasField("task"):
                task = response.task
        if task is None:
            raise RuntimeError("the agent answered with a Message, not a Task")
        if task.status.state not in TERMINAL:
            # §4.2: a holder reads the link from the Task in its terminal state.
            task = await client.get_task(GetTaskRequest(id=task.id))
        if tamper and isinstance(transport, _RewritingTransport) and not transport.rewrites:
            raise RuntimeError("tamper requested but no response carried a text part")
        return Exchange(card=card, task=task)


# ── Holder verification (§8) ────────────────────────────────────────────────


@dataclass
class Verdict:
    ok: bool
    step: int | None
    reason: str
    ctx_id: str | None
    detail: str
    result: ArtifactVerification | None = None
    status: ArtifactStatus | None = None
    body: Mapping[str, Any] | None = None


class Holder:
    """A holder with a registry allowlist and the agent DIDs it trusts."""

    def __init__(self, registries: Mapping[str, str], trusted_agents: set[str]):
        # authority → base URL. A Card or a link never widens this (§9, §13.5).
        self._registries = dict(registries)
        self._trusted = set(trusted_agents)

    async def _retrieve(self, ctx_id: str) -> dict[str, Any]:
        authority = _ctx_authority(ctx_id)
        base = self._registries.get(authority)
        if base is None:
            raise PermissionError(f"registry {authority} is not on the holder's allowlist")
        async with AcdpClient(base) as registry:
            # retrieve_raw enforces RFC-ACDP-0006 §4.1 step 7 (served ctx_id == requested).
            return await registry.retrieve_raw(ctx_id)

    @staticmethod
    def evidence_from(raw: Mapping[str, Any]) -> dict[str, Any] | None:
        """The retrieval's lifecycle history as an ``acdp-evidence/1`` bundle.

        The bundle is untrusted packaging: acdp-verifier-py re-verifies every
        event's producer signature and ``ctx_id`` binding itself.
        """
        body = raw["body"]
        state = raw.get("registry_state") or {}
        entry: dict[str, Any] = {"body": body}
        events = state.get("lifecycle_events")
        if events:
            entry["lifecycle_events"] = events
        return {
            "evidence_version": "acdp-evidence/1",
            "roots": [body["ctx_id"]],
            "exported_at": _now_ms(),
            "contexts": {body["ctx_id"]: entry},
        }

    async def verify(
        self,
        artifact: Mapping[str, Any],
        *,
        card_extensions: list[dict[str, Any]] | None,
        task_id: str | None,
        context_id: str | None,
    ) -> Verdict:
        link = (artifact.get("metadata") or {}).get(LINK_KEY)
        ctx_id = link.get("ctx_id") if isinstance(link, Mapping) else None
        try:
            raw = await self._retrieve(ctx_id) if ctx_id else {"body": {}}
            result = verify_artifact(
                raw["body"],
                artifact,
                trusted_agents=self._trusted,
                card_extensions=card_extensions,
                task_id=task_id,
                context_id=context_id,
                registry_state=raw.get("registry_state"),
                evidence=self.evidence_from(raw) if ctx_id else None,
            )
        except ArtifactMismatch as exc:
            return Verdict(False, exc.step, exc.reason, ctx_id, str(exc))
        except (AcdpError, PermissionError) as exc:
            return Verdict(False, None, type(exc).__name__, ctx_id, str(exc))
        return Verdict(
            True,
            None,
            "verified",
            ctx_id,
            "all §8 checks passed",
            result,
            result.status,
            raw["body"],
        )

    async def recheck_status(self, ctx_id: str) -> ArtifactStatus:
        """§8 step 6 again, later: re-retrieve and re-derive. Nothing is pushed to holders."""
        raw = await self._retrieve(ctx_id)
        return artifact_status(
            ctx_id, registry_state=raw.get("registry_state"), evidence=self.evidence_from(raw)
        )


def expected_agent(card_extensions: list[dict[str, Any]]) -> str | None:
    """The DID the Card says to expect. A pointer, never evidence (§9)."""
    pointer = card_pointer(card_extensions)
    return pointer.agent_id if pointer else None
