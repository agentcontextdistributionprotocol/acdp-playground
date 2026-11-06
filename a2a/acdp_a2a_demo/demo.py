"""RFC-ACDP-0022 end to end: pass, tamper and retraction, against a local registry.

    uv run python -m acdp_a2a_demo.demo [--registry-url http://localhost:8100]

It starts the producer agent, publishes the client's two input datasets, and
runs three A2A tasks:

1. **pass**: the held artifact verifies under §8. ``derived_from`` lists the
   cited inputs.
2. **tamper**: an on-path rewrite changes one Part. The holder fails at §8
   step 4, ``parts_mismatch``.
3. **retraction**: the artifact verifies. The producer then retracts its body
   (RFC-ACDP-0013), and the holder's later re-check reports ``retracted``
   from retrieval.

Exit status 0 means all three behaved as expected. ``--json`` writes the
outcome record that CI uploads.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import socket
import sys
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from acdp import AcdpProducer
from acdp_client import AcdpClient

from acdp_a2a_demo.client import Holder, call_agent, expected_agent, publish_dataset
from acdp_a2a_demo.producer import ProducerSettings, create_app

QUESTION = "Summarize the cited readings"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _line(label: str, value: Any) -> None:
    print(f"    {label:<22} {value}")


def _guard_local(url: str) -> None:
    """Demo bodies are throwaway: refuse anything but a loopback registry."""
    host = httpx.URL(url).host
    if host not in LOCAL_HOSTS and os.environ.get("ACDP_A2A_ALLOW_REMOTE_REGISTRY") != "1":
        sys.exit(f"refusing to publish demo bodies to {url}: use a local registry (see README)")


async def _start_producer(settings: ProducerSettings, port: int) -> tuple[uvicorn.Server, Any]:
    app, ident = await create_app(settings)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            return server, (task, ident)
        await asyncio.sleep(0.05)
    raise RuntimeError("producer agent did not start")


async def run(registry_url: str, registry: str) -> dict[str, Any]:
    _guard_local(registry_url)
    port = _free_port()
    agent_url = f"http://127.0.0.1:{port}"
    seed = secrets.token_bytes(32)
    # The trust anchor reaches the holder out of band, not from the Card.
    producer_did = AcdpProducer.from_seed_did_key(seed).agent_did
    settings = ProducerSettings(
        seed=seed, registry_url=registry_url, registry=registry, public_url=agent_url
    )
    server, (serve_task, ident) = await _start_producer(settings, port)
    holder = Holder({registry: registry_url}, trusted_agents={producer_did})
    outcome: dict[str, Any] = {"agent_id": ident["agent_id"], "runs": {}}
    try:
        print("ACDP × A2A provenance demo (RFC-ACDP-0022)")
        _line("registry", f"{registry} → {registry_url}")
        _line("producer agent", f"{agent_url}  {ident['agent_id']}")

        client_identity = AcdpProducer.generate_did_key()
        async with AcdpClient(registry_url) as reg:
            inputs = [
                await publish_dataset(
                    reg, client_identity, "north-inlet", [21.5, 21.7, 22.0, 22.4]
                ),
                await publish_dataset(reg, client_identity, "south-inlet", [20.9, 21.1, 21.6]),
            ]
        _line("client inputs", ", ".join(inputs))

        # ── 1. pass ────────────────────────────────────────────────────────
        print("\n[1/3] pass: the held artifact verifies")
        ex = await call_agent(agent_url, QUESTION, inputs)
        art = ex.artifacts[0]
        _line("card agentId", expected_agent(ex.card_extensions))
        _line("artifact text", art["parts"][0]["text"])
        v = await holder.verify(
            art,
            card_extensions=ex.card_extensions,
            task_id=ex.task.id,
            context_id=ex.task.context_id,
        )
        derived = list(v.body["derived_from"]) if v.body else None
        ok1 = v.ok and derived == inputs and v.result is not None and v.result.card_checked
        _line("link ctx_id", v.ctx_id)
        _line("verdict", f"{v.reason} ({v.detail})")
        if v.result:
            rec = v.result.record
            _line(
                "record",
                f"{rec['record_version']} salted={rec['salted']} "
                f"embedded={rec['embedded']} a2a={rec['a2a_protocol_version']}",
            )
            _line(
                "checks",
                f"card={v.result.card_checked} task={v.result.task_checked} "
                f"context={v.result.context_checked}",
            )
            _line("status", f"retraction={v.status.retraction} superseded={v.status.superseded}")
        _line("derived_from", derived)
        print(f"  => {'PASS' if ok1 else 'FAIL'}")
        outcome["runs"]["pass"] = {
            "ok": ok1,
            "ctx_id": v.ctx_id,
            "verdict": v.reason,
            "derived_from": derived,
        }

        # ── 2. tamper ──────────────────────────────────────────────────────
        print("\n[2/3] tamper: one Part changed in transit")
        ex = await call_agent(agent_url, QUESTION, inputs, tamper=True)
        art = ex.artifacts[0]
        _line("artifact text", art["parts"][0]["text"])
        v = await holder.verify(
            art,
            card_extensions=ex.card_extensions,
            task_id=ex.task.id,
            context_id=ex.task.context_id,
        )
        ok2 = (not v.ok) and v.step == 4 and v.reason == "parts_mismatch"
        _line("link ctx_id", v.ctx_id)
        _line("verdict", f"step {v.step} {v.reason}")
        _line("detail", v.detail)
        print(
            f"  => {'PASS' if ok2 else 'FAIL'} (rejected at parts_hash, as expected)"
            if ok2
            else "  => FAIL"
        )
        outcome["runs"]["tamper"] = {
            "ok": ok2,
            "ctx_id": v.ctx_id,
            "step": v.step,
            "reason": v.reason,
            "detail": v.detail,
        }

        # ── 3. retraction ──────────────────────────────────────────────────
        print("\n[3/3] retraction: the producer retracts, the holder re-checks")
        ex = await call_agent(agent_url, QUESTION, inputs)
        art = ex.artifacts[0]
        v = await holder.verify(
            art,
            card_extensions=ex.card_extensions,
            task_id=ex.task.id,
            context_id=ex.task.context_id,
        )
        before = v.status.retraction if v.status else None
        _line("link ctx_id", v.ctx_id)
        _line("verdict (before)", f"{v.reason}, retraction={before}")
        async with httpx.AsyncClient(timeout=30) as http:
            r = await http.post(
                f"{agent_url}/demo/retract",
                json={"ctx_id": v.ctx_id, "reason": "sensor calibration fault found"},
            )
            r.raise_for_status()
            _line("producer retracted", r.json())
        status = await holder.recheck_status(v.ctx_id) if v.ctx_id else None
        after = status.retraction if status else None
        ok3 = v.ok and before == "not_retracted" and after == "retracted"
        _line(
            "re-check (retrieval)", f"retraction={after} superseded={status and status.superseded}"
        )
        print(f"  => {'PASS' if ok3 else 'FAIL'}")
        outcome["runs"]["retraction"] = {
            "ok": ok3,
            "ctx_id": v.ctx_id,
            "before": before,
            "after": after,
        }

        outcome["ok"] = ok1 and ok2 and ok3
        print(f"\n{'ALL THREE RUNS BEHAVED AS EXPECTED' if outcome['ok'] else 'DEMO FAILED'}")
        return outcome
    finally:
        server.should_exit = True
        await serve_task


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--registry-url", default=os.environ.get("REGISTRY_URL", "http://localhost:8100")
    )
    p.add_argument(
        "--registry",
        default=os.environ.get("REGISTRY_AUTHORITY", "registry-a.playground.local"),
        help="the registry's ctx_id authority",
    )
    p.add_argument("--json", type=Path, help="write the outcome record here")
    args = p.parse_args(argv)
    outcome = asyncio.run(run(args.registry_url, args.registry))
    if args.json:
        args.json.write_text(json.dumps(outcome, indent=2) + "\n")
    return 0 if outcome.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
