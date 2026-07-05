"""Live-stack conformance probes.

Every other check in this repo asserts against ``httpx.MockTransport`` — the
playground's own hand-authored responses. That is fast and offline, but a mock
can silently encode a contract the real binary does not honor (the reserved
tenant ``422 → 400`` drift is the canonical example). These probes close that
gap: each one drives the **real** registry / control-plane binary (``make
up-full``) and asserts one externally-observable contract, so mock drift surfaces
as a failure instead of staying green.

Each probe takes an :class:`httpx.AsyncClient` plus a :class:`LiveConfig`, raises
:class:`AssertionError` on a contract violation, and returns a one-line summary
on success. They are consumed two ways:

* ``tests/live/`` — pytest wrappers, gated behind ``ACDP_LIVE_STACK`` so the
  offline suite never runs them.
* ``scripts/smoke_test.py --live`` — an operator one-shot against a running stack.

No probe needs an agent-token flow; they exercise contracts reachable with at
most a static admin bearer, which keeps them robust against demo-stack config.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from acdp_client.models import parse_error_envelope
from playground.config import Settings

# A well-formed but (effectively) never-published ctx_id. Reserved-tenant and
# not-found checks only need the *shape* to be valid — the registry rejects the
# reserved tenant / reports not-found before any real lookup matters.
_PROBE_CTX_ID = "acdp://registry-a.playground.local/00000000-0000-4000-8000-0000000000ff"
_ACDP_CONTENT_TYPE = "application/acdp+json"

# Spec lines a conforming registry in this stack may advertise. Both are Final:
# 0.2.0 (receipts / trust hardening) and 0.3.0 (lifecycle, lineage-head
# receipts, transparency log — RFC-ACDP-0011/0012/0013).
_ACCEPTED_ACDP_VERSIONS = frozenset({"0.2.0", "0.3.0"})


@dataclass(frozen=True)
class LiveConfig:
    """Targets for the live probes, resolved from settings + env."""

    registry_url: str
    receipts_registry_url: str
    control_plane_url: str
    admin_token: str
    api_key: str

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "LiveConfig":
        s = settings or Settings()
        admin = s.control_plane_admin_token or os.environ.get(
            "CONTROL_PLANE_ADMIN_TOKEN", "playground-cp-admin"
        )
        # The plain (non-admin) API key gates capability declaration; fall back
        # to the admin bearer, which the AuthGuard also accepts.
        api_key = os.environ.get("CONTROL_PLANE_API_KEY", admin)
        return cls(
            registry_url=s.registry_a_url.rstrip("/"),
            # registry-c is the receipts-profile registry (ACDP 0.2).
            receipts_registry_url=s.registry_c_url.rstrip("/"),
            control_plane_url=(s.control_plane_url or "http://localhost:3001").rstrip("/"),
            admin_token=admin,
            api_key=api_key,
        )


def _encode(ctx_id: str) -> str:
    return quote(ctx_id, safe="")


def _envelope_code(resp: httpx.Response) -> str | None:
    try:
        # json.JSONDecodeError and parse_error_envelope both raise ValueError.
        code, _msg, _details = parse_error_envelope(resp.json())
    except ValueError:
        return None
    return code


# ── registry probes ────────────────────────────────────────────────────────


async def probe_reserved_tenant_400(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """Asserting ``X-Tenant-Id: default`` is refused with **400** schema_violation.

    This is the contract the mock got wrong (it asserted 422). We send the raw
    header — bypassing the client-side guard — to test the *server*.
    """
    url = f"{cfg.registry_url}/contexts/{_encode(_PROBE_CTX_ID)}"
    r = await client.get(url, headers={"X-Tenant-Id": "default"})
    assert r.status_code == 400, (
        f"reserved-tenant: expected 400, got {r.status_code} ({r.text[:200]})"
    )
    code = _envelope_code(r)
    assert code == "schema_violation", (
        f"reserved-tenant: expected code schema_violation, got {code!r}"
    )
    return "reserved tenant → 400 schema_violation"


async def probe_error_envelope_content_type(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """A not-found retrieve returns the ACDP error envelope as ``application/acdp+json``."""
    url = f"{cfg.registry_url}/contexts/{_encode(_PROBE_CTX_ID)}"
    r = await client.get(url)
    assert r.status_code == 404, (
        f"error-envelope: expected 404, got {r.status_code} ({r.text[:200]})"
    )
    ctype = r.headers.get("content-type", "")
    assert _ACDP_CONTENT_TYPE in ctype, (
        f"error-envelope: expected {_ACDP_CONTENT_TYPE}, got {ctype!r}"
    )
    code = _envelope_code(r)
    assert code, f"error-envelope: response carried no parseable error code ({r.text[:200]})"
    return f"not-found → 404 {_ACDP_CONTENT_TYPE} code={code}"


async def probe_receipts_profile_advertised(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """registry-c advertises the receipts profile (RFC-ACDP-0010, ACDP 0.2).

    Provisioning ``[receipt]`` bumps the capabilities document to
    ``acdp_version`` 0.2.0 (or 0.3.0 once the lifecycle/log profiles are on)
    and appends the ``acdp-registry-receipts`` profile
    at ``GET /.well-known/acdp.json``. This is the externally-observable signal
    the S22/S24 scenarios rely on; a registry without the seed silently stays
    0.1.0 and the receipts half would degrade unnoticed without this probe.
    """
    url = f"{cfg.receipts_registry_url}/.well-known/acdp.json"
    r = await client.get(url)
    assert r.status_code == 200, (
        f"receipts-profile: expected 200, got {r.status_code} ({r.text[:200]})"
    )
    body = r.json()
    profiles = body.get("profiles", [])
    assert "acdp-registry-receipts" in profiles, (
        f"receipts-profile: acdp-registry-receipts not advertised (profiles={profiles})"
    )
    # Registries in this stack may run either spec line — both are Final:
    # 0.2.0 (receipts/trust-hardening) or 0.3.0 (lifecycle + head receipts +
    # transparency log, RFC-ACDP-0011/0012/0013).
    assert body.get("acdp_version") in _ACCEPTED_ACDP_VERSIONS, (
        f"receipts-profile: expected acdp_version in {sorted(_ACCEPTED_ACDP_VERSIONS)}, "
        f"got {body.get('acdp_version')!r}"
    )
    return f"receipts profile advertised (acdp_version={body.get('acdp_version')})"


async def probe_did_key_method_advertised(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """registry-c advertises ``did:key`` in ``supported_did_methods`` (ACDP 0.2).

    The did:key ephemeral-agent scenarios can only publish if the registry
    accepts did:key producers; the capabilities document is the contract that
    gates it (an un-advertised did:key publish is rejected
    ``key_resolution_failed``).
    """
    url = f"{cfg.receipts_registry_url}/.well-known/acdp.json"
    r = await client.get(url)
    assert r.status_code == 200, (
        f"did:key-method: expected 200, got {r.status_code} ({r.text[:200]})"
    )
    methods = r.json().get("supported_did_methods", [])
    assert "did:key" in methods, f"did:key-method: did:key not advertised (methods={methods})"
    return f"did:key advertised in supported_did_methods ({methods})"


async def probe_ingest_body_limit_413(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """A publish body over the 1 MiB limit is rejected **413** before parsing."""
    url = f"{cfg.registry_url}/contexts"
    oversized = b'{"x":"' + b"a" * (1_048_576 + 1) + b'"}'
    r = await client.post(url, content=oversized, headers={"Content-Type": "application/json"})
    assert r.status_code == 413, f"body-limit: expected 413, got {r.status_code} ({r.text[:200]})"
    return f"oversized publish ({len(oversized)} bytes) → 413"


# ── control-plane probes ───────────────────────────────────────────────────


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def probe_cp_events_cap(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """``GET /events`` enforces a max ``limit`` of 1000 (CP validation).

    The CP rejects an over-large ``limit`` with a 400 (validation: "limit must
    not be greater than 1000") rather than silently clamping; a within-bound
    request returns the paginated ``{..., nextCursor}`` shape.
    """
    url = f"{cfg.control_plane_url}/events"
    over = await client.get(url, params={"limit": 100_000}, headers=_bearer(cfg.admin_token))
    assert over.status_code == 400, (
        f"events-cap: expected 400 for limit>1000, got {over.status_code} ({over.text[:200]})"
    )
    ok = await client.get(url, params={"limit": 1000}, headers=_bearer(cfg.admin_token))
    assert ok.status_code == 200, (
        f"events-cap: expected 200 for limit=1000, got {ok.status_code} ({ok.text[:200]})"
    )
    assert "nextCursor" in ok.json(), (
        f"events-cap: response missing nextCursor key ({ok.text[:200]})"
    )
    return "events limit capped at 1000 (over-cap → 400, 1000 → 200)"


async def probe_cp_revocations_shape(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """``GET /auth/revocations`` returns the ``{entries, next_cursor}`` feed shape."""
    url = f"{cfg.control_plane_url}/auth/revocations"
    r = await client.get(url, params={"since": 0, "limit": 10}, headers=_bearer(cfg.admin_token))
    assert r.status_code == 200, f"revocations: expected 200, got {r.status_code} ({r.text[:200]})"
    body = r.json()
    assert "entries" in body and "next_cursor" in body, (
        f"revocations: missing entries/next_cursor ({body})"
    )
    assert isinstance(body["entries"], list), "revocations: entries is not a list"
    return f"revocation feed shape ok (entries={len(body['entries'])})"


async def probe_cp_pinned_keys_reload(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """``POST /admin/pinned-keys/reload`` round-trips with an admin bearer."""
    url = f"{cfg.control_plane_url}/admin/pinned-keys/reload"
    r = await client.post(url, headers=_bearer(cfg.admin_token))
    assert r.is_success, f"pinned-key reload: expected 2xx, got {r.status_code} ({r.text[:200]})"
    return f"pinned-key reload → {r.status_code}"


async def probe_capability_algorithm_accepted(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """``ecdsa-p256`` passes the capability DTO's algorithm validation (CP #51).

    Soft check: a full happy-path declaration needs the agent's key pinned on the
    CP, which the demo stack does not provision, so we cannot assert 2xx. Instead
    we assert the request is **not** rejected *because of the algorithm value* —
    i.e. CP #51's ``@IsIn(['ed25519', 'ecdsa-p256'])`` accepts P-256. Any
    signature/auth/policy failure is fine; an algorithm-enum 400 is not.
    """
    url = f"{cfg.control_plane_url}/capabilities"
    body = {
        "agent_did": "did:web:registry-a.playground.local:agents:probe",
        "capability_uri": "urn:acdp:cap:publish:data_snapshot:finance",
        "declared_at": "2026-06-08T00:00:00Z",
        "key_id": "did:web:registry-a.playground.local:agents:probe#key-1",
        "algorithm": "ecdsa-p256",
        "signature": "AAAA",
    }
    r = await client.post(url, json=body, headers=_bearer(cfg.api_key))
    blob = r.text.lower()
    rejected_for_alg = (
        r.status_code == 400
        and "algorithm" in blob
        and ("ed25519" in blob or "isin" in blob or "must be one of" in blob)
    )
    assert not rejected_for_alg, (
        f"capability: ecdsa-p256 was rejected at the algorithm-validation boundary "
        f"({r.status_code} {r.text[:200]})"
    )
    return f"capability ecdsa-p256 not rejected by DTO (status {r.status_code})"


# Ordered registry → control-plane; consumed by the live suite and smoke --live.
REGISTRY_PROBES = (
    probe_reserved_tenant_400,
    probe_error_envelope_content_type,
    probe_ingest_body_limit_413,
    probe_receipts_profile_advertised,
    probe_did_key_method_advertised,
)
CONTROL_PLANE_PROBES = (
    probe_cp_events_cap,
    probe_cp_revocations_shape,
    probe_cp_pinned_keys_reload,
    probe_capability_algorithm_accepted,
)
ALL_PROBES = REGISTRY_PROBES + CONTROL_PLANE_PROBES
