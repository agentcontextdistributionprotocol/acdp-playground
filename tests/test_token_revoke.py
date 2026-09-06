"""Tests for TokenManager: algorithm-aware mint, claim decode, revoke."""

from __future__ import annotations

import base64
import json

import httpx
from acdp import AcdpProducer

from acdp_client.token_manager import TokenManager, _decode_unverified_claims

_DID = "did:web:registry-a.playground.local:agents:t"
_KID = f"{_DID}#key-1"


def _jwt(claims: dict) -> str:
    def seg(d: dict) -> str:
        raw = json.dumps(d).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{seg({'alg': 'HS256'})}.{seg(claims)}.signature"


def _producer():
    return AcdpProducer.from_seed(bytes(range(32)), _DID, _KID)


def test_decode_unverified_claims():
    token = _jwt({"tenant": "tenant-a", "jti": "j-1", "sub": _DID})
    claims = _decode_unverified_claims(token)
    assert claims["tenant"] == "tenant-a"
    assert claims["jti"] == "j-1"


def test_decode_unverified_claims_tolerates_garbage():
    assert _decode_unverified_claims("not-a-jwt") == {}
    assert _decode_unverified_claims("") == {}


class _AuthStub:
    """Minimal challenge→token→revoke registry over httpx.MockTransport."""

    def __init__(self, *, algorithm_seen: list, tenant: str | None = "tenant-a"):
        self.algorithm_seen = algorithm_seen
        self.tenant = tenant
        self.revoked: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/auth/challenge":
            return httpx.Response(
                200,
                json={
                    "nonce": "n-1",
                    "expires_at": 9999999999,
                    "signing_input": "acdp-registry-auth:v1:n-1:did:x:reg:9999999999",
                },
            )
        if path == "/auth/token":
            body = json.loads(request.content)
            self.algorithm_seen.append(body["algorithm"])
            claims = {"jti": "j-1", "sub": _DID}
            if self.tenant:
                claims["tenant"] = self.tenant
            return httpx.Response(
                200,
                json={
                    "token": _jwt(claims),
                    "token_type": "Bearer",
                    "expires_at": 9999999999,
                },
            )
        if path == "/auth/token/revoke":
            jti = json.loads(request.content)["jti"]
            self.revoked.append(jti)
            return httpx.Response(204)
        return httpx.Response(404)


def _tm(stub: _AuthStub) -> TokenManager:
    http = httpx.AsyncClient(transport=httpx.MockTransport(stub.handler))
    return TokenManager(http=http)


async def test_mint_posts_ed25519_algorithm_and_surfaces_claims():
    seen: list = []
    stub = _AuthStub(algorithm_seen=seen)
    tm = _tm(stub)
    cached = await tm.token_for(_producer(), "http://reg.test")
    assert seen == ["ed25519"]
    assert cached.tenant == "tenant-a"
    assert cached.jti == "j-1"
    await tm.aclose()


async def test_revoke_calls_endpoint_and_drops_cache():
    seen: list = []
    stub = _AuthStub(algorithm_seen=seen)
    tm = _tm(stub)
    producer = _producer()
    ok = await tm.revoke(producer, "http://reg.test")
    assert ok is True
    assert stub.revoked == ["j-1"]
    # Cache was dropped → next token_for mints again.
    await tm.token_for(producer, "http://reg.test")
    assert len(seen) == 2  # minted for revoke, then minted again
    await tm.aclose()


async def test_revoke_without_jti_returns_false():
    seen: list = []
    # No tenant + we strip jti by returning a token with no jti claim.
    stub = _AuthStub(algorithm_seen=seen, tenant=None)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/token":
            seen.append("x")
            return httpx.Response(
                200,
                json={
                    "token": _jwt({"sub": _DID}),  # no jti
                    "token_type": "Bearer",
                    "expires_at": 9999999999,
                },
            )
        return stub.handler(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tm = TokenManager(http=http)
    ok = await tm.revoke(_producer(), "http://reg.test")
    assert ok is False
    await tm.aclose()
