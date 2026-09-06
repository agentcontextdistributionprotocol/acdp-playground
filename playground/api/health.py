"""Health endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter

from acdp_client import AcdpClient
from playground.config import get_settings
from playground.version import SERVICE_VERSION

router = APIRouter(tags=["meta"])


@router.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "service": "acdp-playground", "version": SERVICE_VERSION}


@router.get("/readyz")
async def readyz() -> dict:
    """Best-effort: pings both registries."""
    s = get_settings()
    async with AcdpClient(s.registry_a_url) as a, AcdpClient(s.registry_b_url) as b:
        ok_a, ok_b = await asyncio.gather(a.healthz(), b.healthz())
    return {
        "ok": ok_a and ok_b,
        "registry_a": ok_a,
        "registry_b": ok_b,
    }
