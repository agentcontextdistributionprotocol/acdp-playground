"""TokenManager honours a cooperative 429 + Retry-After on the mint path."""

from __future__ import annotations

import base64
import json

import httpx

from acdp import AcdpProducer
from acdp_client.token_manager import ChallengeError, TokenManager

_DID = "did:web:registry-a.playground.local:agents:t"
_KID = f"{_DID}#key-1"


def _jwt(claims: dict) -> str:
    def seg(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'HS256'})}.{seg(claims)}.sig"


def _producer():
    return AcdpProducer.from_seed(bytes(range(32)), _DID, _KID)


def _ok_challenge() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "nonce": "n-1",
            "expires_at": 9999999999,
            "signing_input": "acdp-registry-auth:v1:n-1:did:x:reg:9999999999",
        },
    )


def _ok_token() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "token": _jwt({"jti": "j-1", "sub": _DID}),
            "token_type": "Bearer",
            "expires_at": 9999999999,
        },
    )


async def test_challenge_429_then_retry_succeeds():
    state = {"challenge_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/challenge":
            state["challenge_calls"] += 1
            if state["challenge_calls"] == 1:
                return httpx.Response(
                    429, headers={"retry-after": "0"}, json={"error": {"code": "rate_limited"}}
                )
            return _ok_challenge()
        if request.url.path == "/auth/token":
            return _ok_token()
        return httpx.Response(404)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    cached = await tm.token_for(_producer(), "http://reg.test")
    assert cached.jti == "j-1"
    assert state["challenge_calls"] == 2  # one 429, one cooperative retry
    await tm.aclose()


async def test_challenge_429_without_retry_after_does_not_retry():
    state = {"challenge_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/challenge":
            state["challenge_calls"] += 1
            return httpx.Response(429, json={"error": {"code": "rate_limited"}})
        return httpx.Response(404)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    try:
        await tm.token_for(_producer(), "http://reg.test")
        raise AssertionError("expected ChallengeError")
    except ChallengeError:
        pass
    # No Retry-After header -> no cooperative retry.
    assert state["challenge_calls"] == 1
    await tm.aclose()


async def test_token_429_then_retry_succeeds():
    state = {"token_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/challenge":
            return _ok_challenge()
        if request.url.path == "/auth/token":
            state["token_calls"] += 1
            if state["token_calls"] == 1:
                return httpx.Response(
                    429, headers={"retry-after": "0"}, json={"error": {"code": "rate_limited"}}
                )
            return _ok_token()
        return httpx.Response(404)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    cached = await tm.token_for(_producer(), "http://reg.test")
    assert cached.jti == "j-1"
    assert state["token_calls"] == 2
    await tm.aclose()
