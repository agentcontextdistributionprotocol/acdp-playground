"""End-to-end: POST /runs with a mocked registry + mock LLM, then GET /runs/{id}.

Patches httpx.AsyncClient.post/get so the AcdpClient never talks to a
real registry. Patches LLM_PROVIDER=mock so no API key is needed.
"""

from __future__ import annotations

import itertools
import json
import os
from datetime import UTC, datetime
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id
from tests._bodies import MOCK_BODIES, PLAYGROUND_AUTHORITY

os.environ["LLM_PROVIDER"] = "mock"
os.environ["WEBHOOK_SECRET"] = ""  # disable signature requirement for this test

#: A real signed body, not a hand-written stub — the previous one omitted
#: three fields the SDK's ``Body`` requires.
_RETRIEVE_BODY = MOCK_BODIES["test_run_e2e_mocked.retrieve"]


def _publish_response(counter, authority: str = PLAYGROUND_AUTHORITY) -> dict:
    """A registry-shaped publish response with deterministic ids.

    Seeded rather than ``uuid4()``: a fixture that changes every run makes a
    failure unrepeatable, and the ids still have to satisfy the RFC grammar.
    """
    seed = f"e2e-mocked-publish-{next(counter)}"
    return {
        "ctx_id": synthetic_ctx_id(authority, seed),
        "lineage_id": synthetic_lineage_id(seed),
        "version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "status": "active",
    }


def _fake_post_factory():
    counter = itertools.count(1)

    async def fake_post(self, url, content=None, headers=None, **kw):
        payload = _publish_response(counter)
        req = httpx.Request("POST", url)
        return httpx.Response(201, json=payload, request=req)

    return fake_post


def _fake_get_factory():
    async def fake_get(self, url, *args, **kw):
        # /healthz, /readyz both reachable
        if "healthz" in url:
            return httpx.Response(200, json={"ok": True}, request=httpx.Request("GET", url))
        # context retrieve
        body = _RETRIEVE_BODY
        return httpx.Response(
            200,
            json={"body": body, "registry_state": {"status": "active"}, "registry_receipt": None},
            request=httpx.Request("GET", url),
        )

    return fake_get


@pytest.mark.asyncio
async def test_s1_run_end_to_end_with_mocked_registry():
    from playground.main import app

    with (
        patch.object(httpx.AsyncClient, "post", _fake_post_factory()),
        patch.object(httpx.AsyncClient, "get", _fake_get_factory()),
        TestClient(app) as client,
    ):
        r = client.post("/runs", json={"scenario_id": "s1_single_publish"})
        assert r.status_code == 202, r.text
        run_id = r.json()["run_id"]

        # Drain the SSE stream — TestClient supports it via iter_lines.
        with client.stream("GET", f"/runs/{run_id}/events") as stream:
            saw_complete = False
            for raw in stream.iter_lines():
                if not raw or not raw.startswith("data: "):
                    continue
                payload = json.loads(raw[len("data: ") :])
                if payload.get("type") == "run.complete":
                    saw_complete = True
                    break

        assert saw_complete, "did not see run.complete event"

        detail = client.get(f"/runs/{run_id}").json()
        assert detail["status"] == "complete"
        assert detail["result"]["contexts"], "no contexts in result"
