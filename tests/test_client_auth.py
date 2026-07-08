"""AcdpClient auth integration: token injection + 401 retry."""

from __future__ import annotations

import time

import httpx
import pytest

from acdp import AcdpProducer
from acdp_client import AcdpClient, AcdpHTTPError, TokenManager


def _producer() -> AcdpProducer:
    return AcdpProducer.from_seed(
        bytes(range(2, 34)),
        "did:web:registry.test:agents:bob",
        "did:web:registry.test:agents:bob#key-1",
    )


def _auth_handler_with_retrieve(
    *,
    first_retrieve_status: int = 200,
    second_retrieve_status: int = 200,
    state: dict | None = None,
):
    """Stub that mints tokens and serves retrievals.

    The retrieve handler returns ``first_retrieve_status`` on call #1 and
    ``second_retrieve_status`` on call #2 — lets a test simulate "the
    first cached token is rejected, the refreshed one works".
    """
    state = state or {"retrieves": 0, "tokens": 0, "tokens_seen": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/challenge":
            return httpx.Response(
                200,
                json={
                    "nonce": "n1",
                    "registry_authority": "r",
                    "expires_at": int(time.time()) + 300,
                    "signing_input": "acdp-registry-auth:v1:n1:x:r:1",
                },
                request=request,
            )
        if request.url.path == "/auth/token":
            state["tokens"] += 1
            return httpx.Response(
                200,
                json={
                    "token": f"jwt-{state['tokens']}",
                    "token_type": "Bearer",
                    "expires_at": int(time.time()) + 300,
                },
                request=request,
            )
        if request.url.path.startswith("/contexts/"):
            state["retrieves"] += 1
            state["tokens_seen"].append(request.headers.get("authorization", ""))
            status = first_retrieve_status if state["retrieves"] == 1 else second_retrieve_status
            if status != 200:
                return httpx.Response(status, text="denied", request=request)
            return httpx.Response(
                200,
                json={
                    "body": {
                        "ctx_id": "acdp://r/1",
                        "lineage_id": "lin:sha256:x",
                        "origin_registry": "r",
                        "created_at": "2026-01-01T00:00:00Z",
                        "content_hash": "sha256:abc",
                        "signature": {"algorithm": "ed25519", "key_id": "k", "value": "v"},
                        "version": 1,
                        "agent_id": "did:web:r",
                        "title": "t",
                        "type": "data_snapshot",
                        "visibility": "restricted",
                    },
                    "registry_state": {"status": "active"},
                    "registry_receipt": None,
                },
                request=request,
            )
        return httpx.Response(404, request=request)

    return handler, state


@pytest.mark.asyncio
async def test_client_injects_bearer_token_when_producer_supplied():
    handler, state = _auth_handler_with_retrieve()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    client = AcdpClient(
        "http://registry.test",
        http=http,
        producer=_producer(),
        token_manager=tm,
    )

    await client.retrieve("acdp://r/1")
    assert state["tokens_seen"] == ["Bearer jwt-1"]
    assert state["tokens"] == 1


@pytest.mark.asyncio
async def test_client_retries_once_on_401_with_refreshed_token():
    handler, state = _auth_handler_with_retrieve(
        first_retrieve_status=401, second_retrieve_status=200
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    client = AcdpClient(
        "http://registry.test",
        http=http,
        producer=_producer(),
        token_manager=tm,
    )

    await client.retrieve("acdp://r/1")
    # First call used jwt-1, retry minted jwt-2.
    assert state["tokens_seen"] == ["Bearer jwt-1", "Bearer jwt-2"]
    assert state["tokens"] == 2


@pytest.mark.asyncio
async def test_client_surfaces_repeated_401_without_loop():
    handler, state = _auth_handler_with_retrieve(
        first_retrieve_status=401, second_retrieve_status=401
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    client = AcdpClient(
        "http://registry.test",
        http=http,
        producer=_producer(),
        token_manager=tm,
    )

    with pytest.raises(AcdpHTTPError) as exc:
        await client.retrieve("acdp://r/1")
    assert exc.value.status == 401
    # Exactly two attempts — original + one retry.
    assert state["retrieves"] == 2


@pytest.mark.asyncio
async def test_anonymous_client_sends_no_authorization_header():
    handler, state = _auth_handler_with_retrieve()
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = AcdpClient("http://registry.test", http=http)
    await client.retrieve("acdp://r/1")
    assert state["tokens_seen"] == [""]
    assert state["tokens"] == 0
