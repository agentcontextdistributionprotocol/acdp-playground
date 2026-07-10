"""Settings via pydantic-settings (.env file aware)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Registries
    registry_a_url: str = "http://localhost:8100"
    registry_b_url: str = "http://localhost:8200"
    registry_a_authority: str = "registry-a.playground.local"
    registry_b_authority: str = "registry-b.playground.local"

    # LLM provider
    llm_provider: Literal["openai", "anthropic", "mock"] = "openai"
    llm_model: str = "gpt-4o-mini"
    openai_api_key: str = ""
    anthropic_api_key: str = ""

    # Optional control plane
    control_plane_url: str = ""
    control_plane_hmac_secret: str = ""
    # Admin bearer token for CP admin endpoints (introspection of the
    # revocation feed, pinned-key reload). Matches one of the CP's
    # AUTH_ADMIN_API_KEYS. Empty disables those calls.
    control_plane_admin_token: str = ""

    # Webhook signing — must match the value the registries are launched with
    webhook_secret: str = "playground-dev-secret"

    # ── Registry receipts (RFC-ACDP-0010, ACDP 0.2) ──────────────────────
    # registry-a hosts the receipts profile (verified publish via a pinned
    # did:key/did:web identity, [receipt]/[lifecycle]/[log] configured — see
    # config/registry-a.toml). This is the base64 of its 32-byte Ed25519
    # receipt signing *seed* and MUST equal registry-a.toml's
    # [receipt].signing_key_seed_b64. The receipts scenarios derive the
    # registry's verification key from this seed
    # (AcdpProducer.from_seed(seed).public_key_b64) so they can verify
    # receipts without resolving the registry's (non-web-hosted) did:web DID
    # document. Empty => receipts not provisioned; the scenarios degrade.
    receipt_signing_seed_b64: str = "9NKlBoCp1saUEzMgFonzReHSPbkEN9ba8NrAyR2TYYY="

    # ── V2 protocol features ─────────────────────────────────────────────
    # Default signing algorithm for agents that don't override it.
    default_signature_alg: Literal["ed25519", "ecdsa-p256"] = "ed25519"
    # When true, scenarios that support tenancy attach tenant context
    # (tenant-bound tokens via the registry's tenant_agents config, and
    # X-Tenant-Id fallback for unbound publishes). Off by default so the
    # legacy single-tenant scenarios (S1–S8) are unaffected.
    tenancy_enabled: bool = False
    # JWT signing algorithm the registries/CP are launched with. Purely
    # informational on the playground side (it verifies via JWKS when it
    # needs to); surfaced so scenarios can branch/report.
    jwt_signing_alg: Literal["HS256", "EdDSA"] = "HS256"

    # Logging
    log_format: Literal["pretty", "json"] = "pretty"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── derived ──────────────────────────────────────────────────────────

    @property
    def control_plane_enabled(self) -> bool:
        return bool(self.control_plane_url)

    @property
    def receipts_enabled(self) -> bool:
        return bool(self.receipt_signing_seed_b64)

    def receipt_verification_public_key_b64(self) -> str | None:
        """Derive the receipts registry's Ed25519 receipt *verification* key
        from the shared seed, as standard base64 of the raw 32-byte public
        key.

        Returns ``None`` when no seed is provisioned. The derivation mirrors
        the registry's ``SigningKey::from_bytes(seed)`` (both use
        ed25519-dalek), so the key matches the one the registry signs
        receipts with. Pass the result to ``AcdpVerifier.verify_receipt``.
        """
        if not self.receipt_signing_seed_b64:
            return None
        import base64

        from acdp import AcdpProducer

        seed = base64.b64decode(self.receipt_signing_seed_b64)
        producer = AcdpProducer.from_seed(
            seed, "did:web:receipt-probe:agents:r", "did:web:receipt-probe:agents:r#k"
        )
        return producer.public_key_b64

    def registry_url_for(self, authority: str) -> str | None:
        if authority == self.registry_a_authority:
            return self.registry_a_url
        if authority == self.registry_b_authority:
            return self.registry_b_url
        return None

    def authority_url_map(self) -> dict[str, str]:
        return {
            self.registry_a_authority: self.registry_a_url,
            self.registry_b_authority: self.registry_b_url,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
