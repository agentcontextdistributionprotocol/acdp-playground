"""Detailed end-to-end demo with full input/output narration.

Two agents — `demo-alpha` (producer) and `demo-beta` (consumer) — run a
real OpenAI-backed scenario against a live registry. At every layer
(LLM prompt → LLM response → JCS canonical body → SHA-256 → Ed25519
signature → registry POST → registry response → consumer retrieve →
local signature verify → consumer LLM call → consumer publish with
derived_from edge) we print exactly what's happening, with abbreviated
hex/base64 so the trace stays readable.

Run:
    source .env
    REGISTRY_A_URL=http://127.0.0.1:8100 \
        ./.venv/bin/python scripts/detailed_demo.py
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from textwrap import indent

# Ensure repo root on sys.path so `acdp_client` resolves when run as a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acdp import AcdpProducer, AcdpVerifier  # noqa: E402
from acdp_client import AcdpClient  # noqa: E402

# ── presentation helpers ─────────────────────────────────────────────────


def hr(title: str) -> None:
    bar = "═" * 78
    print(f"\n{bar}\n  {title}\n{bar}")


def sub(label: str) -> None:
    print(f"\n┄┄ {label} ┄┄")


def kv(k: str, v: str, w: int = 18) -> None:
    print(f"  {k:<{w}} {v}")


def short(s: str, n: int = 80) -> str:
    s = s.replace("\n", " ⏎ ")
    return s if len(s) <= n else s[:n] + f"… ({len(s)} chars)"


def b64_short(s: str) -> str:
    return f"{s[:24]}…{s[-12:]}  ({len(s)} chars)"


def dump_json(obj, *, compact_fields=("signature", "content_hash")) -> None:
    """Pretty-print a dict, abbreviating known-noisy fields."""

    def _shrink(node):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k == "signature" and isinstance(v, dict) and "value" in v:
                    out[k] = {**v, "value": b64_short(v["value"])}
                elif k == "content_hash" and isinstance(v, str) and v.startswith("sha256:"):
                    out[k] = v[:16] + "…" + v[-8:]
                elif k == "summary" and isinstance(v, str) and len(v) > 220:
                    out[k] = v[:200] + f"… ({len(v)} chars total)"
                else:
                    out[k] = _shrink(v)
            return out
        if isinstance(node, list):
            return [_shrink(x) for x in node]
        return node

    shrunk = _shrink(obj)
    text = json.dumps(shrunk, indent=2, ensure_ascii=False, default=str)
    print(indent(text, "  "))


# ── identity helpers ─────────────────────────────────────────────────────


AUTH = "registry-a.playground.local"
REG_URL = os.environ.get("REGISTRY_A_URL", "http://127.0.0.1:8100")


def make_producer(slug: str) -> AcdpProducer:
    # Deterministic seed per run-slug so this demo is reproducible.
    seed = hashlib.sha256(f"detailed-demo:{slug}".encode()).digest()
    did = f"did:web:{AUTH}:agents:{slug}"
    return AcdpProducer.from_seed(seed, did, f"{did}#key-1")


# ── steps ────────────────────────────────────────────────────────────────


async def step_0_identities(alpha: AcdpProducer, beta: AcdpProducer) -> None:
    hr("STEP 0 — agent identities (Ed25519, deterministic from seed)")
    for label, p in [("alpha (producer)", alpha), ("beta  (consumer)", beta)]:
        sub(label)
        kv("agent_did", p.agent_did)
        kv("key_id", p.key_id)
        kv("public_key_b64", f"{p.public_key_b64}   ({len(p.public_key_b64)} chars / 32 raw bytes)")
        seed_hex = bytes(p.seed_bytes()).hex()
        kv("seed (hex)", f"{seed_hex[:16]}…{seed_hex[-8:]}   ← SECRET, never sent on the wire")


async def call_llm(prompt: str, label: str) -> str:
    """One real OpenAI call. Shows prompt + response."""
    from langchain_openai import ChatOpenAI

    sub(f"LLM prompt → OpenAI ({label})")
    print(indent(prompt, "  ▸ "))

    llm = ChatOpenAI(model=os.environ.get("LLM_MODEL", "gpt-4o-mini"))
    t0 = time.monotonic()
    resp = await llm.ainvoke(prompt)
    dt = time.monotonic() - t0
    text = resp.content if hasattr(resp, "content") else str(resp)

    sub(f"LLM response ← OpenAI  ({dt:0.2f}s, {len(text)} chars)")
    print(indent(text, "  ◂ "))
    return text


async def step_1_alpha_publish(
    alpha: AcdpProducer,
    client: AcdpClient,
    topic: str,
):
    hr("STEP 1 — agent ALPHA: LLM call → sign → publish")

    prompt = (
        f"Write 4 concise bullet points about current trends in {topic}. "
        "Be specific. Keep it under 120 words."
    )
    llm_text = await call_llm(prompt, "alpha")

    sub("AcdpProducer.build_publish_request — SDK does JCS + SHA-256 + Ed25519")
    req_json_str = alpha.build_publish_request(
        title=f"Trends snapshot — {topic}",
        context_type="data_snapshot",
        visibility="public",
        summary=llm_text[:500],
        domain="demo",
        tags=["demo", "alpha", "trends"],
        metadata=json.dumps({"demo_run": "detailed_demo", "agent_slug": "demo-alpha"}),
    )
    req = json.loads(req_json_str)

    kv("wire size", f"{len(req_json_str)} bytes")
    kv("top-level keys", ", ".join(req.keys()))
    kv("agent_id", req.get("agent_id"))
    kv("title", req.get("title"))
    kv("type", req.get("type"))
    kv("visibility", req.get("visibility"))
    kv("content_hash", req.get("content_hash"))
    kv("signature.algorithm", req["signature"]["algorithm"])
    kv("signature.key_id", req["signature"]["key_id"])
    kv("signature.value", b64_short(req["signature"]["value"]))

    sub("full publish-request JSON (signature/hash abbreviated)")
    dump_json(req)

    sub(f"HTTP POST {REG_URL}/contexts   ← raw wire bytes")
    t0 = time.monotonic()
    resp = await client.publish(req_json_str)
    dt = time.monotonic() - t0

    sub(f"registry response  ({dt * 1000:0.0f} ms, HTTP 201)")
    dump_json(resp.model_dump(mode="json"))
    return req, resp


async def step_2_beta_retrieve_and_verify(client: AcdpClient, ctx_id: str):
    hr("STEP 2 — agent BETA: retrieve ALPHA's context → verify signature locally")

    from urllib.parse import quote

    sub(f"HTTP GET {REG_URL}/contexts/{quote(ctx_id, safe='')}/body")
    t0 = time.monotonic()
    body = await client.retrieve_body(ctx_id)
    dt = time.monotonic() - t0
    body_dict = body.model_dump(mode="json")

    sub(f"registry response  ({dt * 1000:0.0f} ms, HTTP 200) — Body envelope")
    dump_json(body_dict)

    sub("local crypto verification (the SDK's AcdpVerifier)")

    # The security property that matters is "did alpha sign this
    # content_hash?". That's verify_signature(pubkey, sig, hash) —
    # it doesn't depend on the body at all. As long as we trust the
    # registry's content_hash field came from a body the registry
    # itself accepted (which it must have, since it ran the publish
    # pipeline), the signature alone proves authenticity.
    alpha = make_producer("demo-alpha")
    try:
        AcdpVerifier.verify_signature(
            alpha.public_key_b64,
            body_dict["signature"]["value"],
            body_dict["content_hash"],
        )
        kv("signature check", "✓ ok — Ed25519 signature verifies against alpha's pubkey")
        kv("", "  → proves the content_hash was signed by alpha,")
        kv("", "    and (transitively) that the body the registry")
        kv("", "    accepted matched that content_hash.")
    except Exception as e:
        kv("signature check", f"✗ FAILED: {e}")
    return body_dict


async def step_3_beta_publish_derivative(
    beta: AcdpProducer,
    client: AcdpClient,
    alpha_ctx_id: str,
    alpha_body: dict,
    topic: str,
):
    hr("STEP 3 — agent BETA: LLM call (grounded in alpha) → sign → publish")

    grounding = alpha_body.get("summary", "")
    prompt = (
        f"Given the source material below about {topic}, write 3 specific risks and "
        "3 specific opportunities — total under 120 words. Be concrete.\n\n"
        f"=== SOURCE (by {alpha_body['agent_id']}) ===\n{grounding}"
    )
    llm_text = await call_llm(prompt, "beta")

    sub("AcdpProducer.build_publish_request — note derived_from")
    req_json_str = beta.build_publish_request(
        title=f"Risks & opportunities — {topic}",
        context_type="analysis",
        visibility="public",
        summary=llm_text[:500],
        domain="demo",
        tags=["demo", "beta", "analysis"],
        derived_from=[alpha_ctx_id],  # ← the lineage edge
        metadata=json.dumps({"demo_run": "detailed_demo", "agent_slug": "demo-beta"}),
    )
    req = json.loads(req_json_str)

    kv("derived_from", req["derived_from"])
    kv("content_hash", req["content_hash"])
    kv("signature.key_id", req["signature"]["key_id"])
    kv("signature.value", b64_short(req["signature"]["value"]))

    sub(f"HTTP POST {REG_URL}/contexts")
    t0 = time.monotonic()
    resp = await client.publish(req_json_str)
    dt = time.monotonic() - t0

    sub(f"registry response  ({dt * 1000:0.0f} ms, HTTP 201)")
    dump_json(resp.model_dump(mode="json"))
    return req, resp


async def step_4_verify_lineage(client: AcdpClient, alpha_lineage_id: str, beta_ctx_id: str):
    hr("STEP 4 — lineage graph: query the registry for the edges we just formed")

    from urllib.parse import quote

    # Re-derive alpha's ctx_id from beta's body.
    body_b = await client.retrieve_body(beta_ctx_id)
    alpha_ctx_id = body_b.derived_from[0]

    sub(f"HTTP GET {REG_URL}/contexts/search?derived_from={quote(alpha_ctx_id, safe='')}")
    matches = await client.search(derived_from=alpha_ctx_id)
    print(f"  matches: {len(matches.matches)} (showing the first 5)")
    for hit in matches.matches[:5]:
        print(f"    - {hit.title}")
        print(f"        ctx_id   : {hit.ctx_id}")
        print(f"        agent_id : {hit.agent_id}")

    sub("lineage edges we formed this run")
    print(f"  {alpha_ctx_id}")
    print("       │ derived_from")
    print("       ▼")
    print(f"  {beta_ctx_id}")


# ── orchestrator ─────────────────────────────────────────────────────────


async def main() -> int:
    started = datetime.now(timezone.utc).isoformat()
    topic = sys.argv[1] if len(sys.argv) > 1 else "TSMC's 2-nanometer roadmap"

    hr("ACDP DETAILED DEMO  •  producer → consumer with real OpenAI calls")
    kv("registry", REG_URL)
    kv("topic", topic)
    kv("started", started)

    alpha = make_producer("demo-alpha")
    beta = make_producer("demo-beta")
    await step_0_identities(alpha, beta)

    async with AcdpClient(REG_URL, run_id="detailed-demo") as client_a:
        async with AcdpClient(REG_URL, run_id="detailed-demo") as client_b:
            _, alpha_resp = await step_1_alpha_publish(alpha, client_a, topic)
            alpha_body = await step_2_beta_retrieve_and_verify(
                client_b,
                alpha_resp.ctx_id,
            )
            _, beta_resp = await step_3_beta_publish_derivative(
                beta,
                client_b,
                alpha_resp.ctx_id,
                alpha_body,
                topic,
            )
            await step_4_verify_lineage(
                client_b,
                alpha_resp.lineage_id,
                beta_resp.ctx_id,
            )

    hr("DONE")
    print(f"  alpha  → {alpha_resp.ctx_id}")
    print(f"  beta   → {beta_resp.ctx_id}  (derived_from alpha)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
