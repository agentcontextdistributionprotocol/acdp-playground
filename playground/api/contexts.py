"""GET /contexts/{ctx_id} — proxy retrieval through the right registry.

Routes based on the ctx_id's authority. Useful for debugging from the
host without having to hit the registry directly.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from acdp_client import AcdpClient, AcdpHTTPError, CtxIdBindingError
from playground.config import get_settings

router = APIRouter(prefix="/contexts", tags=["contexts"])


def _authority(ctx_id: str) -> str:
    return ctx_id.removeprefix("acdp://").split("/", 1)[0]


@router.get("/{ctx_id:path}")
async def get_context(ctx_id: str) -> JSONResponse:
    settings = get_settings()
    url = settings.registry_url_for(_authority(ctx_id))
    if url is None:
        raise HTTPException(404, f"no registry mapped for authority: {_authority(ctx_id)}")
    async with AcdpClient(url) as client:
        try:
            ctx = await client.retrieve(ctx_id)
        except AcdpHTTPError as e:
            raise HTTPException(e.status, e.body or "registry error") from None
        except CtxIdBindingError as e:
            # RFC-ACDP-0006 §4.1 step 7 failed upstream: the registry answered,
            # but the body it served is not bound to the id we asked for. This
            # is a *bad gateway*, not a bad request — the fault is the upstream
            # registry's, and relaying the body would launder it through the
            # playground. 502 with the reason mirrors the control plane, which
            # answers 502 CONTEXT_ID_MISMATCH / CONTEXT_BINDING_UNVERIFIABLE on
            # its own federation proxy rather than passing the body on.
            raise HTTPException(
                502,
                {
                    "code": "context_binding_failed",
                    "reason": e.reason,
                    "requested_ctx_id": e.requested_ctx_id,
                    "served_ctx_id": e.served_ctx_id,
                    "detail": str(e),
                },
            ) from None
    return JSONResponse(ctx.model_dump(mode="json"))
