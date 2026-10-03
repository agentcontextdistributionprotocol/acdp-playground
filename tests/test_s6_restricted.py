"""S6 — restricted-visibility scenario, end-to-end with mocked registry.

Asserts the three-way outcome contract:
  anonymous       → denied
  outsider (auth) → denied
  audience_member → allowed

The handler mocks the registry's auth + retrieve endpoints; the
scenario, agent factory, AcdpClient, and TokenManager run for real.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from tests._bodies import MOCK_BODIES

os.environ["LLM_PROVIDER"] = "mock"

#: The restricted context this registry serves — a real signed body whose
#: ctx_id the handler also hands back from ``POST /contexts``.
_BODY = MOCK_BODIES["test_s6_restricted.retrieve"]
S6_CTX_ID = _BODY["ctx_id"]


def _retrieve_body() -> dict[str, Any]:
    return {
        "body": _BODY,
        "registry_state": {"status": "active"},
        "registry_receipt": None,
    }


def _build_handler(*, deny_audience_member: bool = False):
    """Mock that simulates a registry with auth + visibility gate.

    ``deny_audience_member`` forces the retrieve gate to deny every
    authenticated caller, including the real audience member — the
    knob the acdp-playground#85 regression test uses to make S6's three
    outcomes come out wrong (``all_correct is False``) without touching
    the scenario itself.
    """

    state = {
        "ctx_id": None,
        "audience": [],
        "tokens": {},  # token -> agent_did
        "next_token_n": 0,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path

        if path == "/auth/challenge":
            body = request.read()
            import json as _json

            agent_id = _json.loads(body)["agent_id"]
            return httpx.Response(
                200,
                json={
                    "nonce": f"n-{agent_id[-5:]}",
                    "registry_authority": "registry-a.playground.local",
                    "expires_at": int(time.time()) + 60,
                    "signing_input": f"acdp-registry-auth:v1:n:{agent_id}:r:1",
                },
                request=request,
            )

        if path == "/auth/token":
            import json as _json

            agent_id = _json.loads(request.read())["agent_id"]
            state["next_token_n"] += 1
            token = f"jwt-{state['next_token_n']}-{agent_id[-10:]}"
            state["tokens"][token] = agent_id
            return httpx.Response(
                200,
                json={
                    "token": token,
                    "token_type": "Bearer",
                    "expires_at": int(time.time()) + 3600,
                },
                request=request,
            )

        if path == "/contexts" and request.method == "POST":
            import json as _json

            req = _json.loads(request.read())
            ctx_id = S6_CTX_ID
            state["ctx_id"] = ctx_id
            state["audience"] = req.get("audience") or []
            return httpx.Response(
                201,
                json={
                    "ctx_id": ctx_id,
                    "lineage_id": _BODY["lineage_id"],
                    "version": 1,
                    "created_at": datetime.now(UTC).isoformat(),
                    "status": "active",
                },
                request=request,
            )

        if path.startswith("/contexts/") and request.method == "GET":
            # Visibility gate
            auth = request.headers.get("authorization", "")
            if not auth.startswith("Bearer "):
                return httpx.Response(404, text="not found", request=request)
            if deny_audience_member:
                return httpx.Response(403, text="not in audience", request=request)
            token = auth[len("Bearer ") :]
            caller = state["tokens"].get(token)
            if caller not in state["audience"]:
                return httpx.Response(403, text="not in audience", request=request)
            return httpx.Response(200, json=_retrieve_body(), request=request)

        return httpx.Response(404, request=request)

    return handler


_REAL_ASYNC_CLIENT = httpx.AsyncClient


class _MockClientFactory:
    """Replacement for ``httpx.AsyncClient`` that always uses our
    MockTransport — regardless of what kwargs the caller passes.

    Holds a reference to the original ``AsyncClient`` so we don't
    recurse when ``patch('httpx.AsyncClient', ...)`` is active."""

    def __init__(self, handler):
        self._handler = handler

    def __call__(self, *args, **kwargs):
        kwargs.pop("transport", None)
        kwargs.pop("timeout", None)
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(self._handler))


@pytest.mark.asyncio
async def test_s6_three_way_outcomes():
    handler = _build_handler()

    # Patch every AsyncClient construction (TokenManager + AcdpClient)
    # to route through our mock transport.
    with patch("httpx.AsyncClient", _MockClientFactory(handler)):
        from playground.scenarios import get_scenario
        from playground.scenarios.models import RunSpec

        scenario = get_scenario("s6_restricted")
        assert scenario is not None and scenario.run is not None

        spec = RunSpec(
            run_id="run-s6-test",
            scenario_id="s6_restricted",
            inputs={"topic": "test margin"},
            registry_mode="single",
        )
        events: asyncio.Queue = asyncio.Queue()
        result = await scenario.run(spec, events)

    outcomes = result.summary["outcomes"]
    assert outcomes["anonymous"]["outcome"] == "denied", outcomes
    assert outcomes["outsider"]["outcome"] == "denied", outcomes
    assert outcomes["audience_member"]["outcome"] == "allowed", outcomes
    assert result.status == "complete"
    assert result.summary["all_assertions_passed"] is True


@pytest.mark.asyncio
async def test_s6_failure_outcome_does_not_truncate_the_sse_stream():
    """Regression for acdp-playground#85.

    S6 used to emit its own StepEvent(type="run.error", ...) mid-run when
    the three access-control outcomes didn't all come out as expected.
    The SSE generator (playground/api/runs.py) ends the stream on the
    FIRST run.complete/run.error event from ANY source, so that mid-run
    event truncated the stream before the runner's own real terminal
    run.complete (carrying the actual RunResult.status, per #84) ever
    arrived. Force the audience-member check to fail and drive this
    through the real app + SSE endpoint -- not just scenario.run()
    directly -- so the stream-level bug is actually exercised.
    """
    handler = _build_handler(deny_audience_member=True)

    with patch("httpx.AsyncClient", _MockClientFactory(handler)):
        from playground.main import app

        with TestClient(app) as client:
            r = client.post("/runs", json={"scenario_id": "s6_restricted"})
            assert r.status_code == 202, r.text
            run_id = r.json()["run_id"]

            seen_types: list[str | None] = []
            final_payload: dict[str, Any] | None = None
            with client.stream("GET", f"/runs/{run_id}/events") as stream:
                for raw in stream.iter_lines():
                    if not raw or not raw.startswith("data: "):
                        continue
                    payload = json.loads(raw[len("data: ") :])
                    seen_types.append(payload.get("type"))
                    if payload.get("type") in ("run.complete", "run.error"):
                        final_payload = payload
                        break

            assert "run.error" not in seen_types, (
                "S6's own mid-run outcomes event must never use the "
                f"terminal run.error type -- saw {seen_types}"
            )
            assert final_payload is not None, "stream ended with no terminal event"
            assert final_payload["type"] == "run.complete", (
                "the run's real terminal event must still arrive, not be "
                f"truncated by a mid-run event -- saw {seen_types}"
            )
            assert final_payload["status"] == "failed"

            detail = client.get(f"/runs/{run_id}").json()
            assert detail["status"] == "failed"
            assert detail["result"]["summary"]["all_assertions_passed"] is False
