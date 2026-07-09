"""Shared helpers used by scenario implementations.

Centralizes the boilerplate of: deterministic identity from
``run_id+slug``, picking the right :class:`AcdpClient` per registry,
optional bearer-token auth, and building a per-run authority → client
map for cross-registry resolution.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Literal

from acdp import AcdpProducer

try:  # P-256 producer is only present on newer SDK builds
    from acdp import AcdpP256Producer
except ImportError:  # pragma: no cover - exercised only on stale SDKs
    AcdpP256Producer = None  # type: ignore[assignment, misc]

from acdp_client import AcdpClient, TokenManager
from acdp_client.client import TenantHeaderMode
from acdp_client.models import StepEvent
from acdp_client.signing import ALG_ED25519, ALG_P256, Producer

from playground.agents import LangChainAgent
from playground.config import Settings, get_settings
from playground.scenarios.models import RunSpec

Registry = Literal["a", "b"]
SignatureAlg = Literal["ed25519", "ecdsa-p256"]


def did_for(authority: str, slug: str) -> str:
    return f"did:web:{authority}:agents:{slug}"


def key_id_for(authority: str, slug: str) -> str:
    return f"{did_for(authority, slug)}#key-1"


def _p256_seed(seed: bytes) -> bytes:
    """Coerce a 32-byte digest into a valid P-256 private scalar.

    ``AcdpP256Producer.from_seed`` rejects a seed that is zero or ≥ the
    curve order (probability ≈ 2⁻³²). On the rare rejection we re-hash
    deterministically so identity stays reproducible for a given run.
    """
    if AcdpP256Producer is None:  # pragma: no cover
        raise RuntimeError(
            "ECDSA-P256 requested but the installed acdp SDK lacks "
            "AcdpP256Producer — rebuild acdp-py (maturin) to enable it."
        )
    candidate = seed
    for _ in range(8):
        try:
            AcdpP256Producer.from_seed(
                candidate, "did:web:probe:agents:x", "did:web:probe:agents:x#k"
            )
            return candidate
        except ValueError:
            candidate = hashlib.sha256(candidate).digest()
    raise ValueError("could not derive a valid P-256 scalar from seed")


def producer_for(
    spec: RunSpec,
    slug: str,
    authority: str,
    *,
    algorithm: SignatureAlg = ALG_ED25519,
) -> Producer:
    """Build a deterministic producer for ``slug`` on ``authority``.

    ``algorithm`` selects the signer type: Ed25519 (default) or
    ECDSA-P256. Both share the same seed source so a slug's identity is
    stable within a run regardless of algorithm choice at the DID level
    (the public key differs, which is expected).
    """
    seed = spec.agent_seed(slug)
    did = did_for(authority, slug)
    key_id = key_id_for(authority, slug)
    if algorithm == ALG_P256:
        return AcdpP256Producer.from_seed(_p256_seed(seed), did, key_id)
    return AcdpProducer.from_seed(seed, did, key_id)


class AgentBundle:
    """Per-run cache of AcdpClient instances + authority map.

    Each ``(registry, producer-or-anonymous)`` pair gets its own
    :class:`AcdpClient`; cross-registry retrieval is wired up via
    :meth:`authority_map`. Tokens are minted lazily via the shared
    :class:`TokenManager`.
    """

    def __init__(self, settings: Settings, run_id: str):
        self._settings = settings
        self._run_id = run_id
        # Key: (registry, producer_did_or_None, tenant_id, tenant_mode) —
        # anonymous clients cache under None did. Tenant params are part of
        # the key so a "conflict" client (always-send header) doesn't alias
        # the normal fallback client for the same producer.
        self._clients: dict[tuple[Registry, str | None, str | None, str], AcdpClient] = {}
        self._token_manager: TokenManager | None = None

    def _registry_url(self, registry: Registry) -> str:
        return self._settings.registry_a_url if registry == "a" else self._settings.registry_b_url

    @property
    def token_manager(self) -> TokenManager:
        return self._ensure_token_manager()

    def _ensure_token_manager(self) -> TokenManager:
        if self._token_manager is None:
            self._token_manager = TokenManager()
        return self._token_manager

    def client(
        self,
        registry: Registry,
        *,
        producer: Producer | None = None,
        tenant_id: str | None = None,
        tenant_header_mode: TenantHeaderMode = "fallback",
    ) -> AcdpClient:
        """Return an :class:`AcdpClient` for the registry, authenticated
        as ``producer`` when supplied.

        ``tenant_id`` + ``tenant_header_mode`` control the ``X-Tenant-Id``
        fallback header (see :class:`AcdpClient`).
        """
        key: tuple[Registry, str | None, str | None, str] = (
            registry,
            producer.agent_did if producer else None,
            tenant_id,
            tenant_header_mode,
        )
        if key not in self._clients:
            kwargs: dict = {
                "run_id": self._run_id,
                "tenant_id": tenant_id,
                "tenant_header_mode": tenant_header_mode,
            }
            if producer is not None:
                kwargs["producer"] = producer
                kwargs["token_manager"] = self._ensure_token_manager()
            self._clients[key] = AcdpClient(self._registry_url(registry), **kwargs)
        return self._clients[key]

    def anonymous_client(
        self,
        registry: Registry,
        *,
        tenant_id: str | None = None,
        tenant_header_mode: TenantHeaderMode = "fallback",
    ) -> AcdpClient:
        """Anonymous client for the registry — for outsider-perspective
        tests that should be denied access to restricted contexts.
        """
        return self.client(registry, tenant_id=tenant_id, tenant_header_mode=tenant_header_mode)

    def authority_map(
        self,
        *,
        producer: Producer | None = None,
        tenant_id: str | None = None,
        tenant_header_mode: TenantHeaderMode = "fallback",
    ) -> dict[str, AcdpClient]:
        """Map authority → client for cross-registry resolution.

        When ``producer`` is supplied, both authority clients are
        authenticated as that producer; otherwise anonymous clients
        are used.
        """
        return {
            self._settings.registry_a_authority: self.client(
                "a",
                producer=producer,
                tenant_id=tenant_id,
                tenant_header_mode=tenant_header_mode,
            ),
            self._settings.registry_b_authority: self.client(
                "b",
                producer=producer,
                tenant_id=tenant_id,
                tenant_header_mode=tenant_header_mode,
            ),
        }

    async def aclose(self) -> None:
        await asyncio.gather(*(c.aclose() for c in self._clients.values()))
        if self._token_manager is not None:
            await self._token_manager.aclose()


def make_langchain_agent(
    spec: RunSpec,
    events: asyncio.Queue[StepEvent],
    bundle: AgentBundle,
    *,
    slug: str,
    registry: Registry = "a",
    authority: str | None = None,
    authenticated: bool = False,
    algorithm: SignatureAlg = ALG_ED25519,
    tenant_id: str | None = None,
    tenant_header_mode: TenantHeaderMode = "fallback",
) -> LangChainAgent:
    """Build a LangChain-backed agent.

    Set ``authenticated=True`` to attach a :class:`TokenManager` —
    required for publishing/retrieving restricted-visibility contexts.
    ``algorithm`` picks the signer (Ed25519 or ECDSA-P256). ``tenant_id``
    /``tenant_header_mode`` drive the ``X-Tenant-Id`` fallback header.
    """
    settings = get_settings()
    auth = authority or (
        settings.registry_a_authority if registry == "a" else settings.registry_b_authority
    )
    producer = producer_for(spec, slug, auth, algorithm=algorithm)
    bound = producer if authenticated else None
    client = bundle.client(
        registry,
        producer=bound,
        tenant_id=tenant_id,
        tenant_header_mode=tenant_header_mode,
    )
    return LangChainAgent(
        producer,
        client,
        events,
        spec.run_id,
        authority_map=bundle.authority_map(
            producer=bound,
            tenant_id=tenant_id,
            tenant_header_mode=tenant_header_mode,
        ),
        slug=slug,
    )


__all__ = [
    "AgentBundle",
    "did_for",
    "key_id_for",
    "make_langchain_agent",
    "producer_for",
]
