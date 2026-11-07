"""FastAPI app entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from playground import logging_setup
from playground.api import contexts, health, registry_proxy, runs, scenarios, webhooks
from playground.config import get_settings
from playground.control_plane import get_control_plane
from playground.quota import reset_quota_store
from playground.security import ApiKeyMiddleware
from playground.version import SERVICE_VERSION

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging_setup.configure(settings.log_level, settings.log_format)
    log.info(
        "starting acdp-playground (registry_a=%s registry_b=%s llm=%s api_key=%s quota_store=%s)",
        settings.registry_a_url,
        settings.registry_b_url,
        settings.llm_provider,
        "required" if settings.playground_require_api_key else "optional",
        "postgres" if settings.database_url else "memory",
    )
    yield
    log.info("stopping acdp-playground")
    await get_control_plane(settings).aclose()
    await registry_proxy.aclose()
    await reset_quota_store()


app = FastAPI(
    title="ACDP Playground",
    version=SERVICE_VERSION,
    description="Runs ACDP scenarios. Spins agents, streams events, owns run lifecycle.",
    lifespan=lifespan,
)

# Starlette runs the last-added middleware first: CORS stays outermost so a
# browser preflight is answered before the key gate, which covers every route
# except /healthz and /webhooks/acdp (playground/security.py).
app.add_middleware(ApiKeyMiddleware)
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
app.include_router(registry_proxy.router)


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
            "/registries/{a|b}/... (allow-listed registry reads)",
            "/webhooks/acdp (registry -> playground)",
        ],
    }
