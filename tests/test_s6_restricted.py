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
import os
import time
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import httpx
import pytest

os.environ["LLM_PROVIDER"] = "mock"


def _retrieve_body(ctx_id: str, visibility: str = "restricted") -> dict[str, Any]:
    return {
        "body": {
            "ctx_id": ctx_id,
            "lineage_id": "lin:sha256:s6",
            "origin_registry": "registry-a.playground.local",
            "created_at": datetime.now(UTC).isoformat(),
            "content_hash": "sha256:s6",
            "signature": {"algorithm": "ed25519", "key_id": "k", "value": "v"},
            "version": 1,
            "agent_id": "did:web:registry-a.playground.local:agents:confidant-producer",
            "title": "Confidential — internal margin analysis",
            "type": "analysis",
            "visibility": visibility,
        },
        "registry_state": {"status": "active"},
        "registry_receipt": None,
    }


def _build_handler():
    """Mock that simulates a registry with auth + visibility gate."""

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
            ctx_id = "acdp://registry-a.playground.local/s6-context"
            state["ctx_id"] = ctx_id
            state["audience"] = req.get("audience") or []
            return httpx.Response(
                201,
                json={
                    "ctx_id": ctx_id,
                    "lineage_id": "lin:sha256:s6",
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
            token = auth[len("Bearer ") :]
            caller = state["tokens"].get(token)
            if caller not in state["audience"]:
                return httpx.Response(403, text="not in audience", request=request)
            return httpx.Response(200, json=_retrieve_body(state["ctx_id"]), request=request)

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
