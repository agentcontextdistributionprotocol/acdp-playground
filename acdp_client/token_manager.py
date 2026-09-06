"""ACDP registry bearer-token manager.

Implements the challenge → sign → token flow against an ACDP registry,
caches issued tokens per ``(agent_did, registry_base_url)``, refreshes
proactively before expiry, and retries once on a 401.

Wire types live in ``acdp-registry-rs/crates/acdp-registry-types/src/auth.rs``;
the canonical challenge signing input is

    acdp-registry-auth:v1:{nonce}:{agent_id}:{authority}:{expires_at}

The Rust SDK's :meth:`acdp.AcdpProducer.sign_challenge` builds the
base64 Ed25519 signature directly from that string.

Design notes
------------

* **Per-(agent, registry) cache.** Each registry signs its own JWTs
  with its own secret. A token issued by registry-a is meaningless to
  registry-b, so we key the cache accordingly.

* **Proactive refresh.** When ``now + leeway >= expires_at`` we acquire
  a new token *before* sending the next request, instead of paying for
  one 401 round-trip per refresh window. Leeway defaults to 30s which
  matches the registry's own ``token_leeway_seconds``.

* **Single-flight per key.** An ``asyncio.Lock`` per cache key ensures
  that concurrent requests trigger at most one challenge/token round
  trip per agent+registry; the rest wait for the lock and reuse the
  resulting token.

* **Reactive retry.** A second 401 after a fresh token means a real
  authorization problem (audience mismatch, revoked key, …); we
  surface that as :class:`TokenAuthError` instead of looping.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

import httpx

from acdp_client.retry_after import parse_retry_after
from acdp_client.signing import producer_algorithm

if TYPE_CHECKING:
    from acdp_client.signing import Producer

log = logging.getLogger(__name__)

# Transient statuses worth one cooperative wait when the registry sends a
# Retry-After. /auth/challenge is rate-limited per agent_id and answers a
# burst with 429 + Retry-After (registry 2e7b4a5); 503 covers a briefly
# unavailable auth backend.
_RETRYABLE_MINT = {429, 503}
_MAX_MINT_RETRY_DELAY = 30.0


def _decode_unverified_claims(token: str) -> dict[str, object]:
    """Best-effort decode of a JWT's payload **without** verifying it.

    The registry/control plane own verification; the playground only
    peeks at non-authoritative claims (``tenant``, ``jti``) for
    telemetry and to drive revocation. Returns ``{}`` on any decode
    problem so callers never crash on an opaque token.
    """
    try:
        payload_b64 = token.split(".")[1]
    except IndexError:
        return {}
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _normalize_aud(aud_claim: object) -> str | None:
    """Render a JWT ``aud`` claim as a string for telemetry.

    ``aud`` is either a single string or (RFC 7519) an array of strings. We
    flatten an array to a comma-joined string so it logs cleanly; anything
    else (absent / malformed) becomes ``None``. Telemetry only — never used
    for verification.
    """
    if isinstance(aud_claim, str):
        return aud_claim or None
    if isinstance(aud_claim, list):
        joined = ",".join(str(a) for a in aud_claim if a)
        return joined or None
    return None


# ── refresh telemetry ────────────────────────────────────────────────────


class RefreshReason(str, Enum):
    """Why a token mint round trip happened.

    Logged on every mint as ``extra={"refresh_reason": <value>, ...}`` so
    operators can detect abnormal patterns:

    * A spike in ``proactive_refresh`` near the leeway window usually
      means the registry's clock skewed or shortened its token TTL.
    * A spike in ``reactive_401`` means tokens are being rejected by the
      server even when the client believes they're fresh — secret
      rotation, audience mismatch, or revoked key.
    * ``first_use`` is expected on startup or when a new
      ``(agent, registry)`` pair is exercised for the first time.
    """

    FIRST_USE = "first_use"
    PROACTIVE_REFRESH = "proactive_refresh"
    REACTIVE_401 = "reactive_401"


# ── exceptions ───────────────────────────────────────────────────────────


class TokenError(RuntimeError):
    """Base class for token-acquisition errors."""


class ChallengeError(TokenError):
    """The registry refused the challenge request."""


class TokenIssueError(TokenError):
    """The registry refused our signed token request."""


class TokenAuthError(TokenError):
    """A request continued to fail with 401 even after a refreshed token.

    Typically indicates a real authorization problem (audience
    mismatch, revoked key, registry rotated its JWT secret) rather
    than an expired token.
    """


# ── cached token ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CachedToken:
    """A token paired with its registry-declared unix-seconds expiry.

    ``tenant``, ``jti`` and ``aud`` are read from the (unverified) JWT payload
    for observability and to drive revocation; they are never treated as
    authoritative by the playground — the issuing registry/CP own that.

    ``aud`` (the JWT ``aud`` claim) is peeked purely for telemetry: both the
    registry (acdp-registry-rs #24) and the control plane (#48) now bind ``aud``
    to their own authority and reject a token minted for a different one. A
    mismatch surfaces server-side as a 401, which the manager reports as
    :class:`TokenAuthError` after its one reactive re-mint — logging ``aud``
    on mint makes that failure mode diagnosable.
    """

    token: str
    token_type: str
    expires_at: int  # unix seconds
    tenant: str | None = None
    jti: str | None = None
    aud: str | None = None

    def is_fresh(self, leeway_seconds: int) -> bool:
        return time.time() + leeway_seconds < self.expires_at


# ── manager ──────────────────────────────────────────────────────────────


class TokenManager:
    """Per-(agent, registry) token cache with single-flight refresh.

    Multiple agents/registries share one ``TokenManager``; callers
    pass the producer + registry base URL to :meth:`token_for`.
    """

    def __init__(
        self,
        *,
        http: httpx.AsyncClient | None = None,
        leeway_seconds: int = 30,
        timeout: float = 15.0,
    ) -> None:
        self._http = http or httpx.AsyncClient(timeout=timeout)
        self._owns_http = http is None
        self._leeway = leeway_seconds
        self._cache: dict[tuple[str, str], CachedToken] = {}
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}
        # When `invalidate()` is called, remember why so the *next* mint
        # for that key carries the right refresh-reason in telemetry.
        # Cleared as soon as the next mint completes.
        self._pending_reasons: dict[tuple[str, str], RefreshReason] = {}
        self._global_lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # ── public API ───────────────────────────────────────────────────────

    async def token_for(
        self,
        producer: Producer,
        registry_base_url: str,
    ) -> CachedToken:
        """Return a fresh token for ``(producer, registry)``.

        Acquires a single-flight lock so concurrent callers reuse the
        same refreshed token rather than racing the registry. The
        returned ``CachedToken`` is guaranteed to be fresh within
        ``leeway_seconds`` of the call.
        """
        key = (producer.agent_did, registry_base_url.rstrip("/"))
        cached = self._cache.get(key)
        if cached and cached.is_fresh(self._leeway):
            return cached

        lock = await self._lock_for(key)
        async with lock:
            # Recheck under the lock — another coroutine may have refreshed.
            cached = self._cache.get(key)
            if cached and cached.is_fresh(self._leeway):
                return cached
            reason = self._classify_refresh(key, cached)
            fresh = await self._mint(producer, key[1], reason=reason)
            self._cache[key] = fresh
            return fresh

    def invalidate(
        self,
        producer: Producer,
        registry_base_url: str,
        *,
        reason: RefreshReason = RefreshReason.REACTIVE_401,
    ) -> None:
        """Drop the cached token, forcing a refresh on the next call.

        Used by :class:`acdp_client.AcdpClient` when a request returns 401
        even though we believed the cached token was still valid; the
        default ``reason`` reflects that. Other callers can pass a
        different reason (e.g. an admin-driven manual rotation) to keep
        the telemetry distinction clean.
        """
        key = (producer.agent_did, registry_base_url.rstrip("/"))
        self._cache.pop(key, None)
        self._pending_reasons[key] = reason

    def _classify_refresh(
        self,
        key: tuple[str, str],
        cached: CachedToken | None,
    ) -> RefreshReason:
        """Pick the refresh reason for the imminent mint.

        Explicit pending reasons (set by :meth:`invalidate`) win — they
        carry signal the cache state can no longer recover (e.g.
        ``REACTIVE_401`` after a server-side rejection). Otherwise:

        * no prior cached token  → ``FIRST_USE``
        * stale cached token     → ``PROACTIVE_REFRESH``
        """
        pending = self._pending_reasons.pop(key, None)
        if pending is not None:
            return pending
        return RefreshReason.PROACTIVE_REFRESH if cached is not None else RefreshReason.FIRST_USE

    # ── internals ────────────────────────────────────────────────────────

    async def _lock_for(self, key: tuple[str, str]) -> asyncio.Lock:
        async with self._global_lock:
            lock = self._locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[key] = lock
            return lock

    async def _post_cooperative(
        self,
        url: str,
        json_body: dict,
        *,
        reason: RefreshReason,
        producer: Producer,
        registry_base_url: str,
        kind: str,
    ) -> httpx.Response:
        """POST ``json_body`` with one cooperative retry on a rate limit.

        A 429/503 carrying a parseable ``Retry-After`` (RFC 9110) earns a
        single capped wait + retry — exactly the contract the registry's
        per-agent challenge throttle expects. Any other status (including a
        second 429) is returned to the caller to handle.
        """
        resp = await self._http.post(url, json=json_body)
        if resp.status_code not in _RETRYABLE_MINT:
            return resp
        delay = parse_retry_after(resp.headers.get("retry-after"), now=time.time())
        if delay is None:
            return resp
        wait = min(delay, _MAX_MINT_RETRY_DELAY)
        log.info(
            "acdp token mint rate-limited; honouring Retry-After",
            extra={
                "event": "acdp.token.mint.retry",
                "refresh_reason": reason.value,
                "agent_did": producer.agent_did,
                "registry_base_url": registry_base_url,
                "kind": kind,
                "status": resp.status_code,
                "retry_after_seconds": wait,
            },
        )
        await asyncio.sleep(wait)
        return await self._http.post(url, json=json_body)

    async def _mint(
        self,
        producer: Producer,
        registry_base_url: str,
        *,
        reason: RefreshReason,
    ) -> CachedToken:
        """Run one full challenge → sign → token round trip.

        Emits two structured INFO log records for each attempt so
        operators can correlate refresh-reason patterns to outcomes:

        * ``event=acdp.token.mint.start`` — request observed
        * ``event=acdp.token.mint.success`` — JWT issued
        * ``event=acdp.token.mint.failure`` — challenge or token POST
          failed (raised as a TokenError after logging)
        """
        started_at = time.monotonic()
        log_extra: dict[str, object] = {
            "event": "acdp.token.mint.start",
            "refresh_reason": reason.value,
            "agent_did": producer.agent_did,
            "registry_base_url": registry_base_url,
        }
        log.info("acdp token mint started", extra=log_extra)

        # Step 1 — challenge
        ch_url = f"{registry_base_url}/auth/challenge"
        ch_req = {"agent_id": producer.agent_did}
        try:
            ch_resp = await self._post_cooperative(
                ch_url,
                ch_req,
                reason=reason,
                producer=producer,
                registry_base_url=registry_base_url,
                kind="challenge",
            )
        except httpx.HTTPError as e:
            self._log_failure(reason, producer, registry_base_url, "challenge_transport", str(e))
            raise ChallengeError(f"POST {ch_url} failed: {e}") from e
        if not ch_resp.is_success:
            self._log_failure(
                reason,
                producer,
                registry_base_url,
                "challenge_status",
                f"status={ch_resp.status_code}",
            )
            raise ChallengeError(f"POST {ch_url} -> {ch_resp.status_code}: {ch_resp.text[:300]}")
        ch = ch_resp.json()
        try:
            nonce = ch["nonce"]
            expires_at = int(ch["expires_at"])
            signing_input = ch["signing_input"]
        except (KeyError, ValueError) as e:
            self._log_failure(
                reason,
                producer,
                registry_base_url,
                "challenge_malformed",
                str(e),
            )
            raise ChallengeError(f"malformed challenge: {e}: {ch}") from None

        # Step 2 — sign with the agent's key (via the SDK). The signer may
        # be Ed25519 or ECDSA-P256; the wire `algorithm` must match.
        algorithm = producer_algorithm(producer)
        signature = producer.sign_challenge(signing_input)

        # Step 3 — exchange signature for JWT
        tk_url = f"{registry_base_url}/auth/token"
        tk_req = {
            "agent_id": producer.agent_did,
            "key_id": producer.key_id,
            "nonce": nonce,
            "expires_at": expires_at,
            "algorithm": algorithm,
            "signature": signature,
        }
        try:
            tk_resp = await self._post_cooperative(
                tk_url,
                tk_req,
                reason=reason,
                producer=producer,
                registry_base_url=registry_base_url,
                kind="token",
            )
        except httpx.HTTPError as e:
            self._log_failure(
                reason,
                producer,
                registry_base_url,
                "token_transport",
                str(e),
            )
            raise TokenIssueError(f"POST {tk_url} failed: {e}") from e
        if not tk_resp.is_success:
            self._log_failure(
                reason,
                producer,
                registry_base_url,
                "token_status",
                f"status={tk_resp.status_code}",
            )
            raise TokenIssueError(f"POST {tk_url} -> {tk_resp.status_code}: {tk_resp.text[:300]}")
        tk = tk_resp.json()
        try:
            token = tk["token"]
            claims = _decode_unverified_claims(token)
            tenant = claims.get("tenant")
            cached = CachedToken(
                token=token,
                token_type=tk.get("token_type", "Bearer"),
                expires_at=int(tk["expires_at"]),
                tenant=tenant if isinstance(tenant, str) else None,
                jti=claims.get("jti") if isinstance(claims.get("jti"), str) else None,
                aud=_normalize_aud(claims.get("aud")),
            )
        except (KeyError, ValueError) as e:
            self._log_failure(
                reason,
                producer,
                registry_base_url,
                "token_malformed",
                str(e),
            )
            raise TokenIssueError(f"malformed token response: {e}: {tk}") from None

        ttl_seconds = cached.expires_at - int(time.time())
        elapsed_ms = int((time.monotonic() - started_at) * 1000)
        log.info(
            "acdp token mint succeeded",
            extra={
                "event": "acdp.token.mint.success",
                "refresh_reason": reason.value,
                "algorithm": algorithm,
                "agent_did": producer.agent_did,
                "registry_base_url": registry_base_url,
                "tenant": cached.tenant,
                "aud": cached.aud,
                "expires_at": cached.expires_at,
                "ttl_seconds": ttl_seconds,
                "elapsed_ms": elapsed_ms,
            },
        )
        return cached

    # ── revocation (RFC 7009 semantics; registry POST /auth/token/revoke) ──

    async def revoke(
        self,
        producer: Producer,
        registry_base_url: str,
    ) -> bool:
        """Revoke the cached token for ``(producer, registry)``.

        Mints a token first if none is cached (so there is a ``jti`` to
        revoke), then calls ``POST /auth/token/revoke`` authenticated as
        the token owner. Drops the token from the cache afterwards so the
        next request mints a fresh one. Returns ``True`` on a 2xx/204.

        The registry enforces an owner-match gate: an agent can only
        revoke tokens issued to its own DID.
        """
        base = registry_base_url.rstrip("/")
        cached = await self.token_for(producer, base)
        if not cached.jti:
            log.warning("cannot revoke: token for %s carries no jti", producer.agent_did)
            return False
        url = f"{base}/auth/token/revoke"
        headers = {
            "Authorization": f"Bearer {cached.token}",
            "Content-Type": "application/json",
        }
        try:
            resp = await self._http.post(url, json={"jti": cached.jti}, headers=headers)
        except httpx.HTTPError as e:
            log.warning("token revoke %s failed: %s", url, e)
            self.invalidate(producer, base, reason=RefreshReason.REACTIVE_401)
            return False
        # Always drop the local copy — revoked or not, we don't want to
        # keep handing out a token we just tried to kill.
        self.invalidate(producer, base, reason=RefreshReason.REACTIVE_401)
        if resp.is_success:
            log.info(
                "token revoked",
                extra={
                    "event": "acdp.token.revoke",
                    "agent_did": producer.agent_did,
                    "registry_base_url": base,
                    "jti": cached.jti,
                },
            )
            return True
        log.warning("token revoke %s -> %s: %s", url, resp.status_code, resp.text[:200])
        return False

    def _log_failure(
        self,
        reason: RefreshReason,
        producer: Producer,
        registry_base_url: str,
        failure_kind: str,
        detail: str,
    ) -> None:
        log.warning(
            "acdp token mint failed",
            extra={
                "event": "acdp.token.mint.failure",
                "refresh_reason": reason.value,
                "agent_did": producer.agent_did,
                "registry_base_url": registry_base_url,
                "failure_kind": failure_kind,
                "detail": detail[:300],
            },
        )


# ── module-level singleton (optional convenience) ────────────────────────


_default: TokenManager | None = None


def default_token_manager() -> TokenManager:
    """Return a process-wide :class:`TokenManager`.

    Most call sites should instantiate their own; the singleton is a
    convenience for short scripts and the playground's runner.
    """
    global _default
    if _default is None:
        _default = TokenManager()
    return _default
