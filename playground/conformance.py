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

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from acdp import AcdpCanonicalizer, AcdpProducer

from acdp_client.models import parse_error_envelope
from playground.config import Settings

# A well-formed but (effectively) never-published ctx_id. Reserved-tenant and
# not-found checks only need the *shape* to be valid — the registry rejects the
# reserved tenant / reports not-found before any real lookup matters.
_PROBE_CTX_ID = "acdp://registry-a.playground.local/00000000-0000-4000-8000-0000000000ff"
# A well-formed, never-published ctx_id on the receipts registry's own
# authority, for the lifecycle-endpoint probe (a retract of a context that does
# not exist / is not the caller's must fail closed with the ACDP envelope).
_RECEIPTS_PROBE_CTX_ID = "acdp://registry-a.playground.local/00000000-0000-4000-8000-0000000000fe"
_ACDP_CONTENT_TYPE = "application/acdp+json"

# The receipts profile (RFC-ACDP-0010 §11) cannot be advertised below this
# spec line: a bare registry stays 0.1.0 and only a configured [receipt]
# signer lifts it. Asserted as a MINIMUM, not an exact set — the registry
# computes its own acdp_version as a max() over per-feature claims
# (acdp-registry-rs .../server/src/main.rs::ladder_claims), so every new
# RFC raises it and an exact allowlist goes red on each one (#58: 0.5.0
# anchors broke this probe until PR #61 appended the string). Raise this
# floor only when the playground genuinely drops support for a spec line.
_MIN_ACDP_VERSION = (0, 2, 0)

# Spec lines this playground has actually been exercised against. NOT the
# accept/reject gate — anything >= the floor is accepted. Kept so a reader
# can see what is validated vs. merely tolerated, and surfaced in the probe
# summary so an operator sees when a stack is ahead of this list.
_KNOWN_ACDP_VERSIONS = frozenset({"0.2.0", "0.3.0", "0.4.0", "0.5.0"})

_ACDP_VERSION_RE = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")


def _parse_acdp_version(raw: object) -> tuple[int, int, int] | None:
    """Parse ``MAJOR.MINOR.PATCH`` into a comparable tuple; None if malformed."""
    if not isinstance(raw, str):
        return None
    m = _ACDP_VERSION_RE.fullmatch(raw)
    if m is None:
        return None
    return (int(m[1]), int(m[2]), int(m[3]))


# RFC-ACDP-0011/0012/0013 server-profile names, advertised at
# ``GET /.well-known/acdp.json`` when the registry runs the corresponding 0.3.0
# surface. The 0.3.0-endpoint probes below are scoped to when the profile is
# actually advertised: advertised-but-broken is a hard failure (mock drift),
# not-advertised is a documented skip (a legitimately-0.2.0 registry).
_LIFECYCLE_PROFILE = "acdp-registry-lifecycle"
_HEAD_RECEIPTS_PROFILE = "acdp-registry-head-receipts"
_LOG_PROFILE = "acdp-registry-transparency-log"

# Deterministic did:key producer for the stateful 0.3.0 probes. A fixed seed →
# a fixed content_hash → an idempotent republish, so re-running the probe suite
# never unboundedly grows the registry's Merkle log or lineage set.
_PROBE_SEED = hashlib.sha256(b"acdp-playground:conformance:0.3.0-probe").digest()


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
            # registry-a hosts the receipts profile (ACDP 0.2) alongside
            # its legacy did:key/pinned-did:web traffic.
            receipts_registry_url=s.registry_a_url.rstrip("/"),
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
    """registry-a advertises the receipts profile (RFC-ACDP-0010, ACDP 0.2).

    Provisioning ``[receipt]`` bumps the capabilities document's
    ``acdp_version`` above the ``_MIN_ACDP_VERSION`` floor (0.2.0) and appends
    the ``acdp-registry-receipts`` profile at ``GET /.well-known/acdp.json``.
    This is the externally-observable signal the S22/S24 scenarios rely on; a
    registry without the seed silently stays 0.1.0 and the receipts half would
    degrade unnoticed without this probe. Asserted as a minimum, not an exact
    match: the registry's own ``acdp_version`` is a max() over per-feature
    claims, so it legitimately climbs (0.3.0, 0.4.0, 0.5.0, ...) as more RFCs
    land, and this probe should keep passing rather than going red on each one.
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
    raw_version = body.get("acdp_version")
    parsed = _parse_acdp_version(raw_version)
    assert parsed is not None, (
        f"receipts-profile: acdp_version {raw_version!r} is not a MAJOR.MINOR.PATCH version"
    )
    assert parsed >= _MIN_ACDP_VERSION, (
        "receipts-profile: expected acdp_version >= "
        f"{'.'.join(map(str, _MIN_ACDP_VERSION))}, got {raw_version!r}"
    )
    note = "" if raw_version in _KNOWN_ACDP_VERSIONS else " (spec line ahead of the known set)"
    return f"receipts profile advertised (acdp_version={raw_version}){note}"


async def probe_did_key_method_advertised(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """registry-a advertises ``did:key`` in ``supported_did_methods`` (ACDP 0.2).

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


# ── 0.3.0 endpoint probes (RFC-ACDP-0011/0012/0013) ─────────────────────────
#
# These drive the REAL 0.3.0 contracts on registry-a (the receipts/lifecycle/
# log registry). Unlike the read-only probes above they publish a deterministic
# context first where the contract needs live state (a Merkle leaf, a lineage
# head). They HARD-FAIL when the real binary drifts from the shape the offline
# mocks encode — the whole point of the live suite — but scope themselves to the
# advertised profile so a 0.2.0-only registry is a documented skip, not a
# spurious failure.


def _now_ms() -> str:
    """Canonical millisecond-precision RFC 3339 UTC (RFC-ACDP-0001 §5.3)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


async def _advertises(client: httpx.AsyncClient, base_url: str, profile: str) -> bool:
    """Whether the registry at ``base_url`` advertises ``profile`` in its
    ``GET /.well-known/acdp.json`` capabilities document."""
    r = await client.get(f"{base_url}/.well-known/acdp.json")
    assert r.status_code == 200, f"capabilities: expected 200, got {r.status_code} ({r.text[:200]})"
    return profile in (r.json().get("profiles") or [])


async def _publish_probe_context(client: httpx.AsyncClient, cfg: LiveConfig) -> tuple[str, str]:
    """Publish the deterministic did:key probe context to the receipts registry
    and return ``(ctx_id, lineage_id)``.

    The seed is fixed so the content_hash is stable: a re-run idempotently
    replays the same context (RFC-ACDP-0003) rather than growing the log
    unboundedly. Anonymous publish (registry-a admits did:key producers — see
    ``probe_did_key_method_advertised``).
    """
    producer = AcdpProducer.from_seed_did_key(_PROBE_SEED)
    raw = producer.build_publish_request(
        title="conformance 0.3.0 probe context",
        context_type="data_snapshot",
        visibility="public",
        summary="Published by playground.conformance to exercise the 0.3.0 endpoints.",
        domain="markets",
        tags=["conformance", "probe"],
    )
    r = await client.post(
        f"{cfg.receipts_registry_url}/contexts",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code in (200, 201), (
        f"probe publish: expected 200/201, got {r.status_code} ({r.text[:200]})"
    )
    body = r.json()
    return body["ctx_id"], body["lineage_id"]


async def probe_log_checkpoint_signed(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """``GET /log/checkpoint`` returns a signed RFC-ACDP-0012 §7 tree head.

    The checkpoint is the log's identity-bearing object; a mock that drifts its
    shape (version tag, the ``root_hash`` encoding, or the signature block) would
    silently break every ``verify_log_checkpoint`` consumer. Stateless — a signed
    head exists even for an empty tree.
    """
    if not await _advertises(client, cfg.receipts_registry_url, _LOG_PROFILE):
        return f"{_LOG_PROFILE} not advertised — /log/checkpoint probe skipped"
    r = await client.get(f"{cfg.receipts_registry_url}/log/checkpoint")
    assert r.status_code == 200, (
        f"log-checkpoint: expected 200, got {r.status_code} ({r.text[:200]})"
    )
    c = r.json()
    assert c.get("checkpoint_version") == "acdp-log/1", (
        f"log-checkpoint: checkpoint_version {c.get('checkpoint_version')!r} != acdp-log/1"
    )
    assert isinstance(c.get("tree_size"), int), f"log-checkpoint: tree_size not an int ({c!r})"
    assert str(c.get("root_hash", "")).startswith("sha256:"), (
        f"log-checkpoint: root_hash not a sha256: fingerprint ({c.get('root_hash')!r})"
    )
    assert c.get("log_id"), "log-checkpoint: missing log_id"
    sig = c.get("signature") or {}
    assert sig.get("algorithm") == "ed25519", (
        f"log-checkpoint: signature.algorithm {sig.get('algorithm')!r} != ed25519"
    )
    assert sig.get("key_id") and sig.get("value"), "log-checkpoint: signature missing key_id/value"
    return f"/log/checkpoint signed (acdp-log/1, tree_size={c['tree_size']})"


async def probe_log_proof_inclusion_and_consistency(
    client: httpx.AsyncClient, cfg: LiveConfig
) -> str:
    """``GET /log/proof`` serves both a §9 inclusion proof and a consistency
    proof in their closed RFC-ACDP-0012 shapes.

    Publishes the probe context so the tree has ≥1 leaf, reads the live tree
    size from the checkpoint, then pins the exact member names the SDK's
    ``verify_log_inclusion`` / ``verify_log_consistency`` consume — including the
    §9.1 step-4 ``tree_size`` binding between the proof and its embedded
    checkpoint. A drifted proof shape fails here instead of surfacing as a
    mysterious ``invalid_log_proof`` in a consumer.
    """
    if not await _advertises(client, cfg.receipts_registry_url, _LOG_PROFILE):
        return f"{_LOG_PROFILE} not advertised — /log/proof probe skipped"
    ctx_id, _ = await _publish_probe_context(client, cfg)
    ck = (await client.get(f"{cfg.receipts_registry_url}/log/checkpoint")).json()
    size = ck["tree_size"]
    assert isinstance(size, int) and size >= 1, (
        f"log-proof: tree still empty after publish (tree_size={size!r})"
    )

    # Inclusion by ctx_id (the consumer, visibility-gated surface).
    inc = await client.get(f"{cfg.receipts_registry_url}/log/proof", params={"ctx_id": ctx_id})
    assert inc.status_code == 200, (
        f"log-proof(inclusion): expected 200, got {inc.status_code} ({inc.text[:200]})"
    )
    ip = inc.json()
    for k in ("log_id", "leaf_index", "tree_size", "inclusion_path", "log_checkpoint"):
        assert k in ip, f"log-proof(inclusion): missing {k!r} ({ip})"
    assert isinstance(ip["inclusion_path"], list), "log-proof(inclusion): inclusion_path not a list"
    assert ip["log_checkpoint"].get("checkpoint_version") == "acdp-log/1", (
        "log-proof(inclusion): embedded checkpoint not acdp-log/1"
    )
    assert ip["tree_size"] == ip["log_checkpoint"]["tree_size"], (
        "log-proof(inclusion): §9.1 step-4 tree_size binding violated"
    )

    # Consistency 1 → current size against the retained root.
    con = await client.get(
        f"{cfg.receipts_registry_url}/log/proof", params={"first": 1, "second": size}
    )
    assert con.status_code == 200, (
        f"log-proof(consistency): expected 200, got {con.status_code} ({con.text[:200]})"
    )
    cp = con.json()
    for k in (
        "log_id",
        "first_tree_size",
        "second_tree_size",
        "consistency_path",
        "log_checkpoint",
    ):
        assert k in cp, f"log-proof(consistency): missing {k!r} ({cp})"
    assert isinstance(cp["consistency_path"], list), (
        "log-proof(consistency): consistency_path not a list"
    )
    assert cp["first_tree_size"] == 1 and cp["second_tree_size"] == size, (
        f"log-proof(consistency): sizes {cp['first_tree_size']}→{cp['second_tree_size']} != 1→{size}"
    )
    assert cp["second_tree_size"] == cp["log_checkpoint"]["tree_size"], (
        "log-proof(consistency): second_tree_size not bound to the embedded checkpoint"
    )
    return f"/log/proof inclusion(leaf={ip['leaf_index']}) + consistency(1→{size})"


async def probe_head_receipt_on_current(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """``GET /lineages/{id}/current`` carries a signed ``lineage_head_receipt``.

    The head receipt (RFC-ACDP-0011 §5) is a *sibling* member of the retrieval
    envelope; a mock that omits it or reshapes it would break the S30 freshness
    flow silently. Publishes the probe context to guarantee a live lineage head,
    then pins the ``acdp-lhr/1`` member shape and its lineage binding.
    """
    if not await _advertises(client, cfg.receipts_registry_url, _HEAD_RECEIPTS_PROFILE):
        return f"{_HEAD_RECEIPTS_PROFILE} not advertised — /current head-receipt probe skipped"
    _, lineage_id = await _publish_probe_context(client, cfg)
    # The client interpolates the lineage_id into the path verbatim (a
    # ``lin:sha256:<hex>`` id has no path-breaking ``/``); mirror that here.
    r = await client.get(f"{cfg.receipts_registry_url}/lineages/{lineage_id}/current")
    assert r.status_code == 200, f"current: expected 200, got {r.status_code} ({r.text[:200]})"
    full = r.json()
    hr = full.get("lineage_head_receipt")
    assert hr is not None, (
        "current: head-receipts profile advertised but no lineage_head_receipt member served"
    )
    assert hr.get("receipt_version") == "acdp-lhr/1", (
        f"current(head-receipt): receipt_version {hr.get('receipt_version')!r} != acdp-lhr/1"
    )
    for k in ("registry_did", "lineage_id", "head_ctx_id", "head_version", "head_status", "as_of"):
        assert k in hr, f"current(head-receipt): missing {k!r} ({hr})"
    sig = hr.get("signature") or {}
    assert sig.get("algorithm") == "ed25519" and sig.get("key_id") and sig.get("value"), (
        f"current(head-receipt): malformed signature block ({sig})"
    )
    assert hr["lineage_id"] == lineage_id, (
        f"current(head-receipt): lineage_id binding {hr['lineage_id']!r} != {lineage_id!r}"
    )
    return f"/lineages/{{id}}/current carries acdp-lhr/1 head receipt (head_version={hr['head_version']})"


def _signed_lifecycle_event(signer: AcdpProducer, ctx_id: str, event_type: str) -> str:
    """A validly-signed RFC-ACDP-0013 §5 lifecycle event (self-contained; does
    not pull in the scenario registry). Preimage is the RFC-ACDP-0010 §5
    construction: SHA-256 over JCS(event minus signature), signed as the ASCII
    ``"sha256:<hex>"`` string."""
    event = {
        "event_id": str(uuid.uuid4()),
        "ctx_id": ctx_id,
        "event_type": event_type,
        "occurred_at": _now_ms(),
        "actor": signer.agent_did,
        "reason": "conformance probe — unauthorized retract",
    }
    canonical = AcdpCanonicalizer.canonicalize(json.dumps(event))
    preimage = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    event["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "value": signer.sign_challenge(preimage),
    }
    return json.dumps(event)


async def probe_retract_endpoint_fails_closed(client: httpx.AsyncClient, cfg: LiveConfig) -> str:
    """``POST /contexts/{id}/retract`` exists and fails an unauthorized retract
    closed with the RFC-ACDP-0007 error envelope.

    Sends a well-formed, validly-signed lifecycle event from a *stranger*
    did:key naming a context that is not theirs (and does not exist). The §6
    pipeline MUST refuse it — never a 2xx, and never a bare 404/405 route miss:
    the response MUST be the ``application/acdp+json`` envelope with a parseable
    code. This proves the endpoint is wired to real authorization/existence
    checks, catching a mock that stubbed retract as an unconditional success.
    """
    if not await _advertises(client, cfg.receipts_registry_url, _LIFECYCLE_PROFILE):
        return f"{_LIFECYCLE_PROFILE} not advertised — /retract probe skipped"
    stranger = AcdpProducer.from_seed_did_key(
        hashlib.sha256(b"acdp-playground:conformance:retract-stranger").digest()
    )
    ctx_id = _RECEIPTS_PROBE_CTX_ID
    event_json = _signed_lifecycle_event(stranger, ctx_id, "retracted")
    r = await client.post(
        f"{cfg.receipts_registry_url}/contexts/{quote(ctx_id, safe='')}/retract",
        content='{"event":' + event_json + "}",
        headers={"Content-Type": "application/json"},
    )
    assert not r.is_success, (
        f"retract: an unauthorized retract of a non-existent context unexpectedly "
        f"succeeded ({r.status_code} {r.text[:200]})"
    )
    assert r.status_code in (400, 401, 403, 404, 409, 422), (
        f"retract: unexpected status {r.status_code} ({r.text[:200]})"
    )
    ctype = r.headers.get("content-type", "")
    assert _ACDP_CONTENT_TYPE in ctype, (
        f"retract: expected the {_ACDP_CONTENT_TYPE} envelope, got {ctype!r} ({r.text[:200]})"
    )
    code = _envelope_code(r)
    assert code, f"retract: response carried no parseable error code ({r.text[:200]})"
    return f"/contexts/{{id}}/retract fails closed → {r.status_code} {code}"


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


# Ordered registry → 0.3.0 endpoints → control-plane; consumed by the live
# suite and smoke --live.
REGISTRY_PROBES = (
    probe_reserved_tenant_400,
    probe_error_envelope_content_type,
    probe_ingest_body_limit_413,
    probe_receipts_profile_advertised,
    probe_did_key_method_advertised,
)
# RFC-ACDP-0011/0012/0013 endpoint contracts on registry-a. Real probes: they
# hard-fail on drift wherever the profile is advertised (mock-drift detection).
ENDPOINT_0_3_0_PROBES = (
    probe_log_checkpoint_signed,
    probe_log_proof_inclusion_and_consistency,
    probe_head_receipt_on_current,
    probe_retract_endpoint_fails_closed,
)
CONTROL_PLANE_PROBES = (
    probe_cp_events_cap,
    probe_cp_revocations_shape,
    probe_cp_pinned_keys_reload,
    probe_capability_algorithm_accepted,
)
ALL_PROBES = REGISTRY_PROBES + ENDPOINT_0_3_0_PROBES + CONTROL_PLANE_PROBES
