"""Async client for ``acdp-a2a-sidecar``, the Rust JSON-lines bridge to acdp-rs's
``acdp-a2a`` producer (RFC-ACDP-0022).

The ``acdp`` Python wheel exposes no A2A surface, so the producer agent drives
the Rust crate through this subprocess instead of reimplementing RFC-0022. The
sidecar owns every protocol step: chunk assembly, the salted record, signing,
publish-before-the-final-chunk, the Idempotency-Key, the link and fail-open.
This module only moves JSON over its stdin and stdout.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import os
import shutil
from pathlib import Path
from typing import Any

SIDECAR_ENV = "ACDP_A2A_SIDECAR"
_DEFAULT_BUILD = Path(__file__).resolve().parent.parent / "sidecar/target/release/acdp-a2a-sidecar"


class SidecarError(RuntimeError):
    """The sidecar answered ``ok: false``, or died."""


def sidecar_binary() -> str:
    """``$ACDP_A2A_SIDECAR``, else the local cargo build, else ``PATH``."""
    explicit = os.environ.get(SIDECAR_ENV)
    if explicit:
        return explicit
    if _DEFAULT_BUILD.exists():
        return str(_DEFAULT_BUILD)
    found = shutil.which("acdp-a2a-sidecar")
    if found:
        return found
    raise SidecarError(
        "acdp-a2a-sidecar not found: run `make sidecar` in a2a/ or set $ACDP_A2A_SIDECAR"
    )


class Sidecar:
    """One sidecar process: one producer identity, many task sessions."""

    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self._proc = proc
        self._ids = itertools.count(1)
        self._lock = asyncio.Lock()

    @classmethod
    async def start(cls, binary: str | None = None) -> Sidecar:
        proc = await asyncio.create_subprocess_exec(
            binary or sidecar_binary(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            # Sized for a full Task snapshot on one line.
            limit=16 * 1024 * 1024,
        )
        return cls(proc)

    async def call(self, op: str, **fields: Any) -> Any:
        """Send one request and wait for its reply (requests are serialized)."""
        assert self._proc.stdin and self._proc.stdout
        async with self._lock:
            req_id = next(self._ids)
            line = json.dumps({"id": req_id, "op": op, **fields}, ensure_ascii=False)
            self._proc.stdin.write(line.encode() + b"\n")
            await self._proc.stdin.drain()
            raw = await self._proc.stdout.readline()
        if not raw:
            raise SidecarError(f"sidecar exited (rc={self._proc.returncode}) during {op}")
        reply = json.loads(raw)
        if reply.get("id") != req_id:
            raise SidecarError(f"sidecar reply id {reply.get('id')} for request {req_id}")
        if not reply.get("ok"):
            raise SidecarError(f"{op}: {reply.get('error')}")
        return reply.get("result")

    async def close(self) -> None:
        if self._proc.stdin and not self._proc.stdin.is_closing():
            self._proc.stdin.close()
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=5)
        except TimeoutError:
            self._proc.kill()
            await self._proc.wait()
