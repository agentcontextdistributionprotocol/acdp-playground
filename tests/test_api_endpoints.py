"""HTTP-surface tests for the meta/scenario/context/run routers.

These exercise the FastAPI layer (routing, serialization, error mapping)
offline — registry-touching paths are stubbed so no network is used.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from acdp_client import AcdpClient, AcdpHTTPError
from playground.main import app


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


# ── health ───────────────────────────────────────────────────────────────


def test_healthz(client: TestClient):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "service": "acdp-playground"}


def test_readyz_reports_both_registries(client: TestClient):
    # Stub the per-registry ping so /readyz never opens a socket.
    with patch.object(AcdpClient, "healthz", AsyncMock(return_value=True)):
        r = client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body == {"ok": True, "registry_a": True, "registry_b": True}


def test_readyz_not_ok_when_a_registry_is_down(client: TestClient):
    with patch.object(AcdpClient, "healthz", AsyncMock(side_effect=[True, False])):
        r = client.get("/readyz")
    body = r.json()
    assert body["ok"] is False
    assert {body["registry_a"], body["registry_b"]} == {True, False}


# ── scenarios ──────────────────────────────────────────────────────────────


def test_list_scenarios(client: TestClient):
    r = client.get("/scenarios")
    assert r.status_code == 200
    scenarios = r.json()["scenarios"]
    ids = {s["id"] for s in scenarios}
    assert "s1_single_publish" in ids
    # serializer exposes the documented fields
    one = next(s for s in scenarios if s["id"] == "s1_single_publish")
    assert set(one) >= {
        "id",
        "name",
        "description",
        "registry_mode",
        "agent_count",
        "framework",
        "default_inputs",
    }


def test_get_one_scenario(client: TestClient):
    r = client.get("/scenarios/s1_single_publish")
    assert r.status_code == 200
    assert r.json()["id"] == "s1_single_publish"


def test_get_unknown_scenario_404(client: TestClient):
    r = client.get("/scenarios/does_not_exist")
    assert r.status_code == 404
    assert "unknown scenario" in r.json()["detail"]


# ── contexts proxy ─────────────────────────────────────────────────────────


def test_context_unmapped_authority_404(client: TestClient):
    # An authority with no configured registry → 404 before any network call.
    r = client.get("/contexts/unknown.example/abc")
    assert r.status_code == 404
    assert "no registry mapped" in r.json()["detail"]


def test_context_propagates_registry_error_status(client: TestClient):
    err = AcdpHTTPError(403, "forbidden", "http://reg", code="not_authorized")
    with patch.object(AcdpClient, "retrieve", AsyncMock(side_effect=err)):
        # registry-a.playground.local is a mapped authority (config default).
        r = client.get("/contexts/registry-a.playground.local/abc")
    assert r.status_code == 403


# ── runs ───────────────────────────────────────────────────────────────────


def test_get_unknown_run_404(client: TestClient):
    r = client.get("/runs/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404
    assert "unknown run" in r.json()["detail"]


def test_start_unknown_scenario_404(client: TestClient):
    r = client.post("/runs", json={"scenario_id": "nope"})
    assert r.status_code == 404
    assert "unknown scenario" in r.json()["detail"]


def test_events_for_unknown_run_404(client: TestClient):
    r = client.get("/runs/does-not-exist/events")
    assert r.status_code == 404
