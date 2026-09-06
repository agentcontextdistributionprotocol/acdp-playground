"""Offline smoke test.

Exercises the wiring without a running registry or LLM. Verifies:
- All scenario modules import + register cleanly
- AcdpProducer + AcdpVerifier round-trip a publish request
- BasePlaygroundAgent.publish path works against a fake AcdpClient
- The webhook signature path validates a payload that we hand-sign

Run:
    uv run python scripts/smoke_test.py            # offline (in-process stubs)
    uv run python scripts/smoke_test.py --live     # + conformance vs. `make up-full`
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sys
from datetime import UTC, datetime
from typing import Any

# Make sure we run from the repo root regardless of CWD.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


async def main(live: bool = False) -> int:
    print("== ACDP playground smoke test ==")
    failures = 0

    failures += await _check_scenarios_load()
    failures += await _check_sdk_round_trip()
    failures += await _check_agent_publish_path()
    failures += await _check_webhook_signature()
    failures += await _check_control_plane_forwarding()
    failures += await _check_p256_round_trip()
    failures += await _check_jcs_number_stability()
    failures += await _check_extended_body_fields()
    failures += await _check_jcs_numeric_vectors()
    failures += await _check_ssrf_guard()
    failures += await _check_supersession_error_parse()
    failures += await _check_idempotent_replay()
    failures += await _check_typed_wire_errors()
    failures += await _check_reserved_tenant_guard()

    if live:
        failures += await _check_live_conformance()

    print()
    if failures:
        print(f"FAIL: {failures} check(s) failed")
        return 1
    print("PASS: all smoke checks passed")
    return 0


async def _check_live_conformance() -> int:
    """Drive the real registry + control-plane binaries (``make up-full``).

    The offline checks above all run against in-process stubs. With ``--live``
    we additionally assert the externally-observable contracts against the real
    services — the layer that catches mock drift (e.g. reserved-tenant 422→400).
    """
    print("\n[live] conformance against the running full stack")
    import httpx

    from playground.conformance import ALL_PROBES, LiveConfig

    cfg = LiveConfig.from_settings()
    print(f"  registry={cfg.registry_url} control_plane={cfg.control_plane_url}")
    failures = 0
    async with httpx.AsyncClient(timeout=15.0) as client:
        for probe in ALL_PROBES:
            try:
                summary = await probe(client, cfg)
                print(f"  ok: {summary}")
            except AssertionError as e:
                print(f"  FAIL: {probe.__name__}: {e}")
                failures += 1
            except Exception as e:  # noqa: BLE001 — unreachable stack, etc.
                print(f"  FAIL: {probe.__name__}: unreachable/error: {e}")
                failures += 1
    return failures


# ── checks ───────────────────────────────────────────────────────────────


async def _check_scenarios_load() -> int:
    print("\n[1/14] scenario catalog loads")
    try:
        from playground.scenarios import list_scenarios
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL import: {e}")
        return 1

    scenarios = list_scenarios()
    expected = {
        "s1_single_publish",
        "s2_producer_consumer",
        "s3_fanout",
        "s4_chain",
        "s5_cross_registry",
        "s6_restricted",
        "s7_supersession",
        "s8_cross_org",
        "s9_p256_publish",
        "s10_tenant_isolation",
        "s11_revocation",
        "s12_key_rotation",
        "s13_policy_deny",
        "s14_domain_pack",
        "s15_supersession_lineage",
        "s16_dataref_ssrf",
        "s17_supersession_authz",
        "s18_idempotency",
        "s19_cp_did_web_p256",
        "s20_reserved_tenant",
        "s21_capabilities_p256",
        "s22_receipts",
        "s23_receipt_tamper",
        "s24_historical_key",
        "s25_did_key",
        "s26_divergence",
        "s27_receipt_key_rotation",
        "s28_lifecycle_retraction",
        "s29_transparency_log",
        "s30_head_receipt_freshness",
        "s31_witness_cosigning",
        "s32_key_revocation",
        "s33_anchors",
    }
    got = {s.id for s in scenarios}
    missing = expected - got
    extras = got - expected
    print(f"  loaded: {sorted(got)}")
    if missing:
        print(f"  MISSING: {sorted(missing)}")
    if extras:
        print(f"  unexpected: {sorted(extras)}")
    return 1 if missing else 0


async def _check_sdk_round_trip() -> int:
    print("\n[2/14] acdp-py SDK round-trip")
    try:
        from acdp import AcdpProducer, AcdpVerifier
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL import: {e}")
        return 1

    seed = bytes(range(32))
    producer = AcdpProducer.from_seed(
        seed,
        "did:web:registry-a.playground.local:agents:smoke",
        "did:web:registry-a.playground.local:agents:smoke#key-1",
    )

    raw = producer.build_publish_request(
        title="Smoke test",
        context_type="data_snapshot",
        visibility="public",
        summary="hello",
        metadata=json.dumps({"k": "v"}),
    )
    req = json.loads(raw)
    body = {k: v for k, v in req.items() if k != "content_hash"}

    # Hash + signature verify against the SDK verifier
    try:
        AcdpVerifier.verify_content_hash(json.dumps(body), req["content_hash"])
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL content_hash: {e}")
        return 1
    try:
        AcdpVerifier.verify_signature(
            producer.public_key_b64,
            body["signature"]["value"],
            req["content_hash"],
        )
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL signature: {e}")
        return 1

    print(f"  ok: agent_did={producer.agent_did}")
    print(f"  ok: content_hash={req['content_hash'][:32]}...")
    return 0


async def _check_agent_publish_path() -> int:
    print("\n[3/14] BasePlaygroundAgent.publish against fake registry")
    try:
        from acdp import AcdpProducer

        from acdp_client.models import PublishResponse
        from playground.agents.base import AgentTask, BasePlaygroundAgent
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL import: {e}")
        return 1

    captured: dict[str, Any] = {}

    class FakeClient:
        async def publish(self, request_json: str, *, idempotency_key=None):
            captured["request"] = json.loads(request_json)
            return PublishResponse(
                ctx_id="acdp://registry-a.playground.local/00000000-0000-4000-8000-000000000001",
                lineage_id="lin:sha256:abc",
                version=1,
                created_at=datetime.now(UTC),
                status="active",
            )

        async def resolve(self, ctx_id, authority_map):  # not used
            raise NotImplementedError

    class StubAgent(BasePlaygroundAgent):
        framework = "stub"

        async def call_llm(self, prompt: str) -> str:
            return f"stub: {prompt[:40]}"

    seed = bytes(range(1, 33))
    producer = AcdpProducer.from_seed(
        seed,
        "did:web:registry-a.playground.local:agents:stub",
        "did:web:registry-a.playground.local:agents:stub#key-1",
    )
    queue: asyncio.Queue = asyncio.Queue()
    agent = StubAgent(producer, FakeClient(), queue, "run-smoke", slug="stub")  # type: ignore[arg-type]

    out = await agent.run(AgentTask(prompt="hello", title="t", override_response="canned"))

    if out.llm_response != "canned":
        print(f"  FAIL override_response: {out.llm_response!r}")
        return 1
    if not captured.get("request"):
        print("  FAIL: client.publish was not called")
        return 1
    if captured["request"]["title"] != "t":
        print(f"  FAIL: title mismatch: {captured['request']['title']!r}")
        return 1

    events: list[str] = []
    while not queue.empty():
        events.append(queue.get_nowait().type)
    print(f"  ok: emitted events={events}")
    print(f"  ok: ctx_id={out.ctx_id}")
    return 0


async def _check_webhook_signature() -> int:
    print("\n[4/14] webhook signature verify")
    secret = "test-secret"
    body = b'{"type":"context_published","agent_id":"did:web:x","ctx_id":"acdp://r/1"}'
    expected = f"sha256={hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}"

    try:
        from playground.api.webhooks import _verify

        _verify(secret, body, expected)
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL valid signature was rejected: {e}")
        return 1

    try:
        from fastapi import HTTPException

        from playground.api.webhooks import _verify as _verify2

        try:
            _verify2(secret, body, "sha256=deadbeef")
        except HTTPException:
            pass
        else:
            print("  FAIL: bad signature was accepted")
            return 1
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL: {e}")
        return 1

    print("  ok: valid signature accepted, bad signature rejected")
    return 0


async def _check_control_plane_forwarding() -> int:
    """Stand up a tiny in-process HTTP stub and assert the playground's
    ControlPlaneClient signs + forwards run lifecycle + webhook payloads
    correctly. Replaces the previous "control-plane stub deferred" gap
    (deferred-plan §13.3)."""
    print("\n[5/14] control-plane forwarding (in-process stub)")

    try:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
    except Exception as e:  # noqa: BLE001
        print(f"  SKIP (starlette/uvicorn missing): {e}")
        return 0

    captured: list[dict[str, Any]] = []

    async def stub_handler(request):
        captured.append(
            {
                "path": request.url.path,
                "headers": dict(request.headers),
                "body": (await request.body()).decode("utf-8"),
            }
        )
        return JSONResponse({"ok": True})

    app = Starlette(
        routes=[
            Route("/runs/started", stub_handler, methods=["POST"]),
            Route("/runs/{run_id}/complete", stub_handler, methods=["POST"]),
            Route("/ingest/acdp", stub_handler, methods=["POST"]),
        ]
    )

    # Pick an ephemeral port and serve in a background task.
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    serve_task = asyncio.create_task(server.serve())
    # Wait for the server to bind.
    for _ in range(50):
        if server.started:
            break
        await asyncio.sleep(0.05)
    else:
        print("  FAIL: stub control-plane never bound")
        server.should_exit = True
        await serve_task
        return 1

    try:
        from playground.config import Settings
        from playground.control_plane import ControlPlaneClient

        settings = Settings(
            control_plane_url=f"http://127.0.0.1:{port}",
            control_plane_hmac_secret="cp-secret",
        )
        client = ControlPlaneClient(settings)

        await client.notify_run_started("r-1", "s4_chain", {"topic": "smoke"})
        await client.notify_run_complete("r-1", "complete", {"contexts": 3})
        await client.forward_webhook(
            b'{"type":"context_published","ctx_id":"acdp://r/1"}',
            headers={"X-ACDP-Event": "context_published"},
        )
        await client.aclose()

        # Verify ordering, paths, signature presence + correctness.
        if len(captured) != 3:
            print(f"  FAIL: expected 3 forwarded requests, got {len(captured)}")
            return 1

        paths = [r["path"] for r in captured]
        if paths != ["/runs/started", "/runs/r-1/complete", "/ingest/acdp"]:
            print(f"  FAIL: unexpected path order: {paths}")
            return 1

        # All three carry HMAC over the body.
        for r in captured:
            sig = r["headers"].get("x-acdp-signature")
            if not sig or not sig.startswith("sha256="):
                print(f"  FAIL: missing/malformed signature on {r['path']}: {sig}")
                return 1
            expected = (
                "sha256="
                + hmac.new(b"cp-secret", r["body"].encode("utf-8"), hashlib.sha256).hexdigest()
            )
            if sig != expected:
                print(f"  FAIL: HMAC mismatch on {r['path']}")
                return 1

        # The webhook forward must preserve the original event header.
        ingest = captured[2]
        if ingest["headers"].get("x-acdp-event") != "context_published":
            print("  FAIL: X-ACDP-Event not preserved on /ingest/acdp")
            return 1

        # Lifecycle payloads carry the right discriminators.
        if "r-1" not in captured[0]["body"] or "s4_chain" not in captured[0]["body"]:
            print(f"  FAIL: runs/started body missing fields: {captured[0]['body']}")
            return 1
        if "complete" not in captured[1]["body"]:
            print(f"  FAIL: runs/complete body missing status: {captured[1]['body']}")
            return 1

        print("  ok: 3 forwarded, all HMAC-verified, event header preserved")
        return 0
    finally:
        server.should_exit = True
        await serve_task


async def _check_p256_round_trip() -> int:
    print("\n[6/14] ECDSA-P256 producer + verifier round-trip")
    try:
        from acdp import AcdpP256Producer, AcdpVerifier
    except ImportError:
        print("  SKIP: SDK lacks AcdpP256Producer (rebuild acdp-py to enable)")
        return 0
    from acdp_client.signing import producer_algorithm, public_key_material, verify_signature

    producer = AcdpP256Producer.from_seed(
        bytes(31) + bytes([1]),
        "did:web:registry-a.playground.local:agents:p256",
        "did:web:registry-a.playground.local:agents:p256#key-1",
    )
    if producer_algorithm(producer) != "ecdsa-p256":
        print("  FAIL: producer_algorithm misdetected")
        return 1
    raw = producer.build_publish_request(title="P256", context_type="analysis")
    req = json.loads(raw)
    if req["signature"]["algorithm"] != "ecdsa-p256":
        print(f"  FAIL: wire algorithm {req['signature']['algorithm']!r}")
        return 1
    body = {k: v for k, v in req.items() if k != "content_hash"}
    try:
        AcdpVerifier.verify_content_hash(json.dumps(body), req["content_hash"])
        ok = verify_signature(
            "ecdsa-p256",
            public_key_material(producer),
            req["signature"]["value"],
            req["content_hash"],
        )
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL verify: {e}")
        return 1
    if not ok:
        print("  FAIL: P-256 signature did not verify")
        return 1
    print("  ok: ecdsa-p256 signed + verified; JWK + DID method available")
    return 0


async def _check_jcs_number_stability() -> int:
    """RFC 8785 number canonicalization must be stable: the same body with a
    float metadata value hashes identically across two independent builds."""
    print("\n[7/14] JCS RFC 8785 numeric canonicalization stability")
    from acdp import AcdpProducer, AcdpVerifier

    producer = AcdpProducer.from_seed(
        bytes(range(32)),
        "did:web:registry-a.playground.local:agents:jcs",
        "did:web:registry-a.playground.local:agents:jcs#key-1",
    )
    meta = json.dumps({"score": 0.1, "ratio": 1.5, "count": 3})

    def build_hash() -> str:
        raw = producer.build_publish_request(
            title="JCS", context_type="data_snapshot", summary="floats", metadata=meta
        )
        return json.loads(raw)["content_hash"]

    h1, h2 = build_hash(), build_hash()
    if h1 != h2:
        print(f"  FAIL: non-deterministic hash {h1[:24]} != {h2[:24]}")
        return 1
    # And the hash verifies.
    raw = producer.build_publish_request(
        title="JCS", context_type="data_snapshot", summary="floats", metadata=meta
    )
    req = json.loads(raw)
    body = {k: v for k, v in req.items() if k != "content_hash"}
    try:
        AcdpVerifier.verify_content_hash(json.dumps(body), req["content_hash"])
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL: float-body content_hash did not verify: {e}")
        return 1
    print(f"  ok: float metadata hashes stably ({h1[:24]}...)")
    return 0


async def _check_extended_body_fields() -> int:
    """The agent threads data_refs / data_period / expires_at into the
    publish request, and omits them when unset."""
    print("\n[8/14] extended body fields (data_refs / data_period / expires_at)")
    from acdp import AcdpProducer

    from acdp_client.models import PublishResponse
    from playground.agents.base import AgentTask, BasePlaygroundAgent

    captured: dict[str, Any] = {}

    class FakeClient:
        async def publish(self, request_json: str, *, idempotency_key=None):
            captured["request"] = json.loads(request_json)
            return PublishResponse(
                ctx_id="acdp://registry-a.playground.local/00000000-0000-4000-8000-000000000002",
                lineage_id="lin:sha256:abc",
                version=1,
                created_at=datetime.now(UTC),
                status="active",
            )

    class StubAgent(BasePlaygroundAgent):
        framework = "stub"

        async def call_llm(self, prompt: str) -> str:
            return "x"

    producer = AcdpProducer.from_seed(
        bytes(range(2, 34)),
        "did:web:registry-a.playground.local:agents:ext",
        "did:web:registry-a.playground.local:agents:ext#key-1",
    )
    agent = StubAgent(producer, FakeClient(), asyncio.Queue(), "run-ext", slug="ext")  # type: ignore[arg-type]
    await agent.run(
        AgentTask(
            prompt="x",
            title="ext",
            context_type="analysis",
            override_response="res",
            data_refs=[{"type": "primary_result", "location": "https://e.com/d.csv"}],
            data_period={"start": "2026-01-01T00:00:00Z", "end": "2026-03-31T23:59:59Z"},
            expires_at="2026-12-31T00:00:00Z",
        )
    )
    req = captured.get("request", {})
    if (
        not req.get("data_refs")
        or req.get("data_period", {}).get("start") != "2026-01-01T00:00:00Z"
    ):
        print(
            f"  FAIL: extended fields not threaded: {req.get('data_refs')} {req.get('data_period')}"
        )
        return 1
    if not str(req.get("expires_at", "")).startswith("2026-12-31"):
        print(f"  FAIL: expires_at not set: {req.get('expires_at')}")
        return 1
    print("  ok: data_refs + data_period + expires_at present on publish request")
    return 0


async def _check_jcs_numeric_vectors() -> int:
    """The Rust JCS canonicalizer (acdp.AcdpCanonicalizer, acdp-py 0.2.0)
    reproduces the RFC's can-011 vectors (negative-zero -> '0', exponential
    bands, integer exactness)."""
    print("\n[9/14] JCS RFC 8785 numeric conformance vectors")
    import hashlib as _hashlib
    from pathlib import Path

    from acdp import AcdpCanonicalizer

    rfc_dir = Path(
        os.environ.get("ACDP_RFC_DIR", os.path.join(ROOT, "..", "agentcontextdistributionprotocol"))
    )
    vectors_path = rfc_dir / "schemas" / "conformance" / "can-011-jcs-numeric-vectors.json"
    if not vectors_path.exists():
        print(f"  SKIP: vectors not found at {vectors_path}")
        return 0
    vectors = json.loads(vectors_path.read_text())["vectors"]
    for vec in vectors:
        got = AcdpCanonicalizer.canonicalize(json.dumps(vec["input"]))
        want = vec["expected"]["canonical_form"]
        if got != want:
            print(f"  FAIL {vec['name']}: {got!r} != {want!r}")
            return 1
        digest = _hashlib.sha256(got.encode("utf-8")).hexdigest()
        if digest != vec["expected"]["sha256_hex"]:
            print(f"  FAIL {vec['name']}: hash mismatch")
            return 1
    print(f"  ok: all {len(vectors)} numeric vectors reproduced")
    return 0


async def _check_ssrf_guard() -> int:
    """The consumer SSRF guard blocks IMDS, mixed-answer DNS, cross-port
    redirects, and non-https — without touching the network."""
    print("\n[10/14] consumer SSRF guard (data_refs)")
    from acdp_client.safe_http import (
        SsrfError,
        SsrfPolicy,
        check_url,
        ip_is_forbidden,
        same_authority,
        screen_host,
    )

    pol = SsrfPolicy.production()
    if ip_is_forbidden("169.254.169.254", pol) is None:
        print("  FAIL: IMDS not blocked")
        return 1
    try:
        screen_host("x", pol, resolver=lambda h: ["203.0.113.10", "10.0.0.1"])
        print("  FAIL: mixed answer not rejected")
        return 1
    except SsrfError:
        pass
    if same_authority("https://a.example/x", "https://a.example:8443/x"):
        print("  FAIL: cross-port treated as same authority")
        return 1
    try:
        check_url("http://a.example/x", pol)
        print("  FAIL: http:// not blocked")
        return 1
    except SsrfError:
        pass
    print("  ok: IMDS + mixed-answer + cross-port + http all blocked")
    return 0


async def _check_supersession_error_parse() -> int:
    """A superseded_target envelope surfaces as SupersededError with reason
    (lineage-takeover prevention contract)."""
    print("\n[11/14] supersession error envelope -> SupersededError")
    import httpx

    from acdp_client.client import AcdpClient, SupersededError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            headers={"content-type": "application/acdp+json"},
            json={"error": {"code": "superseded_target", "details": {"reason": "not_found"}}},
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = AcdpClient("http://reg.test", http=http)
    try:
        await client.publish('{"x":1}')
        print("  FAIL: publish did not raise")
        return 1
    except SupersededError as e:
        if e.reason != "not_found":
            print(f"  FAIL: unexpected reason {e.reason!r}")
            return 1
    finally:
        await client.aclose()
    print("  ok: superseded_target -> SupersededError(reason='not_found')")
    return 0


async def _check_idempotent_replay() -> int:
    """A repeated Idempotency-Key replays one ctx_id; the header is forwarded
    verbatim and never pre-validated (registry #24 contract, client side)."""
    print("\n[12/14] idempotent publish replay")
    import itertools

    import httpx

    from acdp_client.client import AcdpClient

    counter = itertools.count(1)
    by_key: dict[str, str] = {}
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        key = request.headers.get("idempotency-key")
        seen.append(key)
        ctx = by_key.get(key) if key else None
        if ctx is None:
            ctx = f"acdp://reg.test/{next(counter)}"
            if key:
                by_key[key] = ctx
        return httpx.Response(
            200,
            json={
                "ctx_id": ctx,
                "lineage_id": "lin",
                "version": 1,
                "created_at": "2026-06-03T00:00:00Z",
                "status": "active",
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = AcdpClient("http://reg.test", http=http)
    try:
        first = await client.publish("{}", idempotency_key="k")
        second = await client.publish("{}", idempotency_key="k")
        if first.ctx_id != second.ctx_id:
            print(f"  FAIL: duplicate key produced {first.ctx_id} != {second.ctx_id}")
            return 1
        if seen != ["k", "k"]:
            print(f"  FAIL: header not forwarded verbatim: {seen}")
            return 1
    finally:
        await client.aclose()
    print("  ok: duplicate Idempotency-Key -> one replayed ctx_id")
    return 0


async def _check_typed_wire_errors() -> int:
    """not_authorized -> 403 NotAuthorizedError; oversized body -> 413
    PayloadTooLargeError (RFC-ACDP-0007 §5 / registry #24, #26)."""
    print("\n[13/14] typed §5 wire errors (403 not_authorized, 413)")
    import httpx

    from acdp_client.client import (
        AcdpClient,
        NotAuthorizedError,
        PayloadTooLargeError,
    )

    def forbidden(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"content-type": "application/acdp+json"},
            json={"error": {"code": "not_authorized", "message": "no"}},
        )

    def too_large(request: httpx.Request) -> httpx.Response:
        return httpx.Response(413, headers={"content-type": "application/acdp+json"}, content=b"")

    for label, handler, exc in (
        ("not_authorized", forbidden, NotAuthorizedError),
        ("payload_too_large", too_large, PayloadTooLargeError),
    ):
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = AcdpClient("http://reg.test", http=http)
        try:
            await client.publish('{"x":1}')
            print(f"  FAIL: {label} did not raise")
            return 1
        except exc:
            pass
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL: {label} raised {type(e).__name__}, expected {exc.__name__}")
            return 1
        finally:
            await client.aclose()
    print("  ok: 403 -> NotAuthorizedError, 413 -> PayloadTooLargeError")
    return 0


async def _check_reserved_tenant_guard() -> int:
    """The reserved `default` tenant can never be *asserted* (registry 400
    schema_violation / CP 403 not_authorized, mirrored client-side; CP #50)."""
    print("\n[14/14] reserved-tenant guard (default sentinel)")
    from acdp_client import RESERVED_TENANT, AcdpClient, reject_reserved_tenant
    from playground.control_plane import _tenant_header

    if RESERVED_TENANT != "default":
        print(f"  FAIL: RESERVED_TENANT={RESERVED_TENANT!r}, expected 'default'")
        return 1

    # default asserted -> blocked everywhere; absence / real tenant -> allowed.
    try:
        reject_reserved_tenant("default")
        print("  FAIL: reject_reserved_tenant('default') did not raise")
        return 1
    except ValueError:
        pass
    reject_reserved_tenant(None)  # untenanted is legitimate
    reject_reserved_tenant("tenant-a")  # real tenant is legitimate

    try:
        AcdpClient("http://reg.test", tenant_id="default")
        print("  FAIL: AcdpClient(tenant_id='default') did not raise")
        return 1
    except ValueError:
        pass

    try:
        _tenant_header("default")
        print("  FAIL: _tenant_header('default') did not raise")
        return 1
    except ValueError:
        pass
    if _tenant_header("tenant-a") != {"X-Tenant-Id": "tenant-a"}:
        print("  FAIL: _tenant_header('tenant-a') did not stamp the header")
        return 1

    print("  ok: 'default' rejected at guard/client/bridge; None + real allowed")
    return 0


if __name__ == "__main__":
    # `--live` adds a conformance pass against a running `make up-full` stack;
    # without it the smoke test stays fully offline (in-process stubs).
    _live = "--live" in sys.argv[1:]
    sys.exit(asyncio.run(main(live=_live)))
