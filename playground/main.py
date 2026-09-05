"""FastAPI app entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from playground import logging_setup
from playground.api import contexts, health, runs, scenarios, webhooks
from playground.config import get_settings
from playground.control_plane import get_control_plane
from playground.version import SERVICE_VERSION

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging_setup.configure(settings.log_level, settings.log_format)
    log.info(
        "starting acdp-playground (registry_a=%s registry_b=%s llm=%s)",
        settings.registry_a_url,
        settings.registry_b_url,
        settings.llm_provider,
    )
    yield
    log.info("stopping acdp-playground")
    await get_control_plane(settings).aclose()


app = FastAPI(
    title="ACDP Playground",
    version=SERVICE_VERSION,
    description="Runs ACDP scenarios. Spins agents, streams events, owns run lifecycle.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(scenarios.router)
app.include_router(runs.router)
app.include_router(contexts.router)
app.include_router(webhooks.router)


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {
        "service": "acdp-playground",
        "version": app.version,
        "endpoints": [
            "/healthz",
            "/readyz",
            "/scenarios",
            "/scenarios/{id}",
            "/runs (POST)",
            "/runs/{id}",
            "/runs/{id}/events (SSE)",
            "/contexts/{ctx_id}",
            "/webhooks/acdp (registry -> playground)",
        ],
    }
