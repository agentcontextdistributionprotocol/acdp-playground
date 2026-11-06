"""Offline checks for the RFC-0022 demo wiring (no registry needed).

The end-to-end runs (pass, tamper, retraction) are ``make demo`` against a
local registry, which CI runs in .github/workflows/a2a-demo.yml.
"""

from __future__ import annotations

import os

import pytest
from acdp import AcdpProducer
from acdp_verifier.a2a import card_pointer
from acdp_verifier.evidence import validate_evidence

from acdp_a2a_demo import demo
from acdp_a2a_demo.client import Holder, tamper_first_text_part
from acdp_a2a_demo.producer import _Input, analyse
from acdp_a2a_demo.sidecar import Sidecar, SidecarError, sidecar_binary

CTX = "acdp://registry-a.playground.local/00000000-0000-4000-8000-000000000001"


def _have_sidecar() -> bool:
    try:
        return os.path.exists(sidecar_binary())
    except SidecarError:
        return False


needs_sidecar = pytest.mark.skipif(not _have_sidecar(), reason="acdp-a2a-sidecar not built")


def test_analyse_summarizes_verified_inputs():
    text, stats = analyse(
        [
            _Input(CTX, "north", "celsius", [1.0, 2.0, 3.0, 4.0]),
            _Input(CTX, "south", "celsius", [5.0]),
        ],
        "Summarize",
    )
    assert stats["count"] == 5 and stats["min"] == 1.0 and stats["max"] == 5.0
    assert stats["trend"] == "rising"
    assert text.startswith("Summarize: 5 readings from north, south")


def test_analyse_without_inputs_says_so():
    text, stats = analyse([], "Summarize")
    assert stats == {} and "nothing to summarize" in text


def test_tamper_rewrites_exactly_one_text_part():
    doc = {
        "result": {
            "task": {
                "artifacts": [
                    {"parts": [{"text": "mean 3"}, {"text": "untouched"}, {"data": {"mean": 3}}]}
                ]
            }
        }
    }
    assert tamper_first_text_part(doc)
    parts = doc["result"]["task"]["artifacts"][0]["parts"]
    assert parts[0]["text"] != "mean 3" and parts[1]["text"] == "untouched"
    assert not tamper_first_text_part({"result": {"message": {"parts": []}}})


def test_evidence_bundle_packages_the_retrieval():
    body = {
        "ctx_id": CTX,
        "lineage_id": "lin:sha256:" + "0" * 64,
        "origin_registry": "registry-a.playground.local",
        "created_at": "2026-11-06T00:00:00.000Z",
        "content_hash": "sha256:" + "1" * 64,
        "signature": {"algorithm": "ed25519", "key_id": "did:key:z6Mk#z6Mk", "value": "AA=="},
        "version": 1,
        "supersedes": None,
        "agent_id": "did:key:z6Mk",
        "contributors": [],
        "title": "t",
        "type": "analysis",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        "acdp_version": "0.5.0",
    }
    event = {
        "event_id": "00000000-0000-4000-8000-000000000002",
        "ctx_id": CTX,
        "event_type": "retracted",
        "occurred_at": "2026-11-06T00:00:01.000Z",
        "actor": "did:key:z6Mk",
    }
    bare = Holder.evidence_from({"body": body, "registry_state": {"status": "active"}})
    assert bare["evidence_version"] == "acdp-evidence/1" and bare["roots"] == [CTX]
    assert bare["contexts"][CTX] == {"body": body}
    retracted = Holder.evidence_from(
        {"body": body, "registry_state": {"status": "retracted", "lifecycle_events": [event]}}
    )
    assert retracted["contexts"][CTX]["lifecycle_events"] == [event]
    # Only the top-level shape is the demo's; the body itself is checked by the verifier.
    with pytest.raises(Exception, match="body"):
        validate_evidence(retracted)


async def test_holder_refuses_a_registry_off_its_allowlist():
    holder = Holder({"registry-a.playground.local": "http://localhost:1"}, set())
    artifact = {
        "artifactId": "a",
        "parts": [{"text": "x"}],
        "metadata": {
            "io.acdp/provenance": {
                "ctx_id": "acdp://evil.example/00000000-0000-4000-8000-000000000001"
            }
        },
    }
    verdict = await holder.verify(artifact, card_extensions=None, task_id=None, context_id=None)
    assert not verdict.ok and verdict.reason == "PermissionError"


async def test_holder_reports_a_missing_link_at_step_1():
    holder = Holder({}, set())
    verdict = await holder.verify(
        {"artifactId": "a", "parts": [{"text": "x"}]},
        card_extensions=None,
        task_id=None,
        context_id=None,
    )
    assert not verdict.ok and verdict.step == 1 and verdict.reason == "link_failed"


def test_demo_refuses_a_remote_registry(monkeypatch):
    monkeypatch.delenv("ACDP_A2A_ALLOW_REMOTE_REGISTRY", raising=False)
    with pytest.raises(SystemExit):
        demo._guard_local("https://registry.acdp.io")
    demo._guard_local("http://localhost:8100")


@needs_sidecar
async def test_sidecar_identity_and_card_match_the_python_sdk():
    seed = bytes(range(32))
    sc = await Sidecar.start()
    try:
        ident = await sc.call(
            "init",
            seed_hex=seed.hex(),
            registry_url="http://localhost:1",
            registry="registry-a.playground.local",
            a2a_protocol_version="1.0",
            body_type="analysis",
            visibility="public",
            allow_local_http=True,
        )
        did = AcdpProducer.from_seed_did_key(seed).agent_did
        assert ident["agent_id"] == did
        ext = ident["card_extension"]
        assert ext["uri"] == "https://acdp.io/ext/a2a/v1" and ext["required"] is False
        pointer = card_pointer([ext])
        assert pointer is not None and pointer.agent_id == did
        assert pointer.registry == "registry-a.playground.local"

        # A non-final chunk passes through unchanged: nothing publishes before completion.
        await sc.call("begin", task_id="t1", context_id="c1")
        noted = await sc.call(
            "message",
            task_id="t1",
            message={
                "role": "ROLE_USER",
                "messageId": "m",
                "parts": [{"text": "hi"}],
                "metadata": {"io.acdp/inputs": [CTX]},
            },
        )
        assert noted["cited"] == [CTX]
        chunk = {
            "taskId": "t1",
            "contextId": "c1",
            "artifact": {"artifactId": "a1", "parts": [{"text": "partial"}]},
        }
        out = await sc.call("chunk", task_id="t1", chunk=chunk)
        assert out == {"emit": chunk}
        with pytest.raises(SidecarError):
            await sc.call("chunk", task_id="nope", chunk=chunk)
    finally:
        await sc.close()


@needs_sidecar
async def test_sidecar_fails_open_when_the_registry_is_unreachable():
    """§6.2 default: the completing chunk still goes out, linked as failed."""
    sc = await Sidecar.start()
    try:
        await sc.call(
            "init",
            seed_hex="00" * 32,
            registry_url="http://127.0.0.1:1",
            registry="registry-a.playground.local",
            a2a_protocol_version="1.0",
            body_type="analysis",
            visibility="public",
            allow_local_http=True,
        )
        await sc.call("begin", task_id="t", context_id="c")
        chunk = {
            "taskId": "t",
            "contextId": "c",
            "lastChunk": True,
            "artifact": {"artifactId": "a", "parts": [{"text": "done"}]},
        }
        out = await sc.call("chunk", task_id="t", chunk=chunk)
        link = out["emit"]["artifact"]["metadata"]["io.acdp/provenance"]
        assert link["failed"] is True
        assert out["emit"]["artifact"]["parts"] == [{"text": "done"}]
    finally:
        await sc.close()
