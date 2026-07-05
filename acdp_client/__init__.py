"""HTTP client + Pydantic wire types for ACDP registries.

The `acdp` package (built via maturin from acdp-rs/bindings/acdp-py)
owns all crypto. This package adds the async HTTP transport
(:class:`AcdpClient`) and Pydantic aliases for the wire types the
registry returns.
"""

# did:web helpers live in the Rust SDK (acdp-py 0.3.0). Re-export them here so
# playground code resolves a producer's DID document through one import surface
# — the same consumer gate (assertionMethod authorization + algorithm-downgrade
# defense, RFC-ACDP-0008 §3.9) the registry and control plane use server-side.
from acdp import AcdpDid, AcdpDidDocument, DidResolutionError

from acdp_client.client import (
    AcdpClient,
    AcdpHTTPError,
    ImmutableFieldError,
    InvalidLifecycleTransitionError,
    InvalidLogProofError,
    NotAuthorizedError,
    PayloadTooLargeError,
    SupersededError,
)
from acdp_client.identifiers import (
    RESERVED_TENANT,
    is_reserved_tenant,
    is_valid_authority,
    reject_reserved_tenant,
    validate_origin_registry,
)
from acdp_client.models import (
    ERROR_CODES,
    LIFECYCLE_ERROR_CODES,
    SIGNATURE_ERROR_CODES,
    Body,
    CursorError,
    FullContext,
    PublishResponse,
    SearchHit,
    SearchResponse,
    Signature,
    StepEvent,
    WebhookEvent,
    parse_error_envelope,
)
from acdp_client.safe_http import (
    DataRefHashMismatch,
    SsrfError,
    SsrfPolicy,
    fetch_data_ref,
)
from acdp_client.signing import (
    ALG_ED25519,
    ALG_P256,
    is_p256,
    producer_algorithm,
    public_key_material,
    verify_signature,
)
from acdp_client.token_manager import (
    CachedToken,
    ChallengeError,
    RefreshReason,
    TokenAuthError,
    TokenError,
    TokenIssueError,
    TokenManager,
    default_token_manager,
)

__all__ = [
    "ALG_ED25519",
    "ALG_P256",
    "ERROR_CODES",
    "LIFECYCLE_ERROR_CODES",
    "SIGNATURE_ERROR_CODES",
    "AcdpClient",
    "AcdpDid",
    "AcdpDidDocument",
    "AcdpHTTPError",
    "Body",
    "CachedToken",
    "ChallengeError",
    "CursorError",
    "DataRefHashMismatch",
    "DidResolutionError",
    "FullContext",
    "ImmutableFieldError",
    "InvalidLifecycleTransitionError",
    "InvalidLogProofError",
    "NotAuthorizedError",
    "PayloadTooLargeError",
    "PublishResponse",
    "RESERVED_TENANT",
    "RefreshReason",
    "SearchHit",
    "SearchResponse",
    "Signature",
    "SsrfError",
    "SsrfPolicy",
    "StepEvent",
    "SupersededError",
    "TokenAuthError",
    "TokenError",
    "TokenIssueError",
    "TokenManager",
    "WebhookEvent",
    "default_token_manager",
    "fetch_data_ref",
    "is_p256",
    "is_reserved_tenant",
    "is_valid_authority",
    "parse_error_envelope",
    "producer_algorithm",
    "public_key_material",
    "reject_reserved_tenant",
    "validate_origin_registry",
    "verify_signature",
]
