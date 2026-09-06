"""Consumer-side SSRF guard for following ``data_refs[].location`` URLs.

The IP / scheme / redirect-authority **classification** now lives in the Rust
SDK (:class:`acdp.AcdpSsrfPolicy`, exposed in ``acdp-py`` 0.2.0 — see
``acdp-rs/src/safe_http.rs`` and ``acdp-rs/plans/expose-ssrf-jcs-to-bindings``).
This module keeps only the orchestration that *must* stay in the host
language and that the Rust core deliberately does not own:

* **DNS resolution** (injectable for tests) and the **mixed-answer loop** —
  resolve every address and reject the *whole* set if any address is
  forbidden (RFC-ACDP-0006 §7.1). This is orchestration over ``check_ip``,
  not a single predicate, so it stays here (plan D3).
* the **httpx GET** with same-authority redirect enforcement, a follow cap,
  and a response-size bound, and
* the **content_hash verification** of the fetched bytes.

The per-address / per-URL verdicts are delegated to the Rust policy so the
playground no longer maintains a second copy of the forbidden IP ranges and
the ECMAScript number rules. The public names (``check_url``, ``screen_host``,
``same_authority``, ``ip_is_forbidden``, ``fetch``, ``fetch_data_ref``,
``SsrfError``, ``SsrfPolicy``) are unchanged so call sites don't move;
``SsrfError.reason`` now carries the Rust :class:`acdp.SsrfRejected` taxonomy
(``loopback`` / ``private`` / ``imds`` / ``multicast_or_reserved`` /
``non_https`` / ``ip_literal`` / ``invalid_url`` / ``cross_authority``).
"""

from __future__ import annotations

import hashlib
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from acdp import AcdpSsrfPolicy, SsrfRejected

# A resolver maps a hostname to the list of textual IP addresses DNS
# would return. Injectable so tests never touch the network.
Resolver = Callable[[str], list[str]]


class SsrfError(RuntimeError):
    """A fetch was refused by the SSRF guard.

    ``reason`` is a stable machine-readable token so callers/tests can
    assert *why* a fetch was blocked. Classification reasons come from the
    Rust :class:`acdp.SsrfRejected` taxonomy; the orchestration layer adds a
    few transport-level reasons of its own (``dns_failure``,
    ``cross_authority_redirect``, ``response_too_large``, …).
    """

    def __init__(self, reason: str, message: str):
        super().__init__(f"{reason}: {message}")
        self.reason = reason
        self.message = message


class DataRefHashMismatch(RuntimeError):
    """Fetched bytes did not match ``data_ref.content_hash``.

    Mirrors the registry/RFC ``data_ref_hash_mismatch`` code, but this is
    a *consumer* fetch-time check (RFC-ACDP-0008 §4.9): the body itself
    stays valid; the referenced data is simply unverifiable.
    """


@dataclass(frozen=True)
class SsrfPolicy:
    """Knobs for the consumer fetch guard. The default is production-safe.

    The IP/scheme classification is owned by the Rust policy selected via
    :pyattr:`allow_loopback`; the remaining fields are *transport* knobs that
    only the host-language fetch loop enforces.
    """

    allow_loopback: bool = False
    max_redirects: int = 3
    max_bytes: int = 1_048_576  # 1 MB (RFC-ACDP-0006 §7)
    connect_timeout: float = 5.0
    total_timeout: float = 30.0

    @classmethod
    def production(cls) -> SsrfPolicy:
        return cls()

    @classmethod
    def allow_test_loopback(cls) -> SsrfPolicy:
        """Permit loopback (for a local registry/data stack) but still block
        RFC-1918 + link-local/IMDS — maps to the Rust SDK's
        ``SsrfPolicy::allow_test_loopback``.
        """
        return cls(allow_loopback=True)

    def _rust(self) -> AcdpSsrfPolicy:
        """The matching Rust policy that owns the classification verdicts."""
        if self.allow_loopback:
            return AcdpSsrfPolicy.allow_test_loopback()
        return AcdpSsrfPolicy.production()


# ── classification (delegated to the Rust policy) ───────────────────────────


def ip_is_forbidden(ip_text: str, policy: SsrfPolicy) -> str | None:
    """Return the stable Rust SSRF reason if ``ip_text`` is off-limits, else None."""
    try:
        policy._rust().check_ip(ip_text)
        return None
    except SsrfRejected as e:
        return getattr(e, "reason", "blocked")
    except ValueError:
        # The Rust binding raises ValueError for a syntactically invalid IP.
        return "unparseable_ip"


def check_url(url: str, policy: SsrfPolicy) -> None:
    """Validate scheme/userinfo/host shape *before* any DNS resolution.

    Scheme + IP-literal screening is delegated to the Rust policy. The
    userinfo guard stays here: the Rust ``check_url`` does not reject
    credentials in the authority, and a ``user:pass@`` URL is a known
    SSRF/phishing vector, so we keep the defense in depth on the host side.
    """
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise SsrfError("forbidden_userinfo", f"userinfo not allowed in URL: {url}")
    try:
        policy._rust().check_url(url)
    except SsrfRejected as e:
        raise SsrfError(getattr(e, "reason", "blocked"), str(e)) from e


def same_authority(u1: str, u2: str) -> bool:
    """True iff scheme + host (case-insensitive) + *effective port* match.

    A host-only comparison is non-conformant (RFC-ACDP-0006 §7.5): an
    attacker controlling ``host:443`` need not control an internal service
    the same host exposes on ``:8443``. Delegated to the Rust policy's
    ``check_redirect_authority`` (effective-port aware).
    """
    try:
        AcdpSsrfPolicy.production().check_redirect_authority(u1, u2)
        return True
    except (SsrfRejected, ValueError):
        return False


# ── DNS resolution + mixed-answer rejection (stays in the host language) ────


def _default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:  # pragma: no cover - network dependent
        raise SsrfError("dns_failure", f"could not resolve {host}: {e}") from e
    return [info[4][0] for info in infos]


def screen_host(host: str, policy: SsrfPolicy, *, resolver: Resolver | None = None) -> list[str]:
    """Resolve ``host`` and reject the *whole* answer set on any bad address.

    Mixed-answer rejection (RFC-ACDP-0006 §7.1): partial filtering would
    leave the forbidden address in DNS for a reconnect/rebind to exploit.
    This loop is orchestration over the Rust per-address verdict (plan D3).
    """
    resolve = resolver or _default_resolver
    addrs: Iterable[str] = resolve(host)
    addrs = list(addrs)
    if not addrs:
        raise SsrfError("dns_failure", f"no addresses for {host}")
    for ip_text in addrs:
        reason = ip_is_forbidden(ip_text, policy)
        if reason is not None:
            raise SsrfError(
                reason,
                f"{host} resolved to a forbidden address ({ip_text}); "
                "rejecting the entire resolution",
            )
    return addrs


# ── fetch ────────────────────────────────────────────────────────────────────


async def fetch(
    url: str,
    *,
    policy: SsrfPolicy | None = None,
    resolver: Resolver | None = None,
    client: httpx.AsyncClient | None = None,
) -> bytes:
    """Fetch ``url`` under the SSRF guard, returning the response bytes.

    Screens the URL + every redirect hop, enforces same-authority
    redirects with a follow cap, and bounds the response size. Raises
    :class:`SsrfError` on any policy violation.
    """
    pol = policy or SsrfPolicy.production()
    owns = client is None
    http = client or httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(pol.total_timeout, connect=pol.connect_timeout),
    )
    try:
        current = url
        for _ in range(pol.max_redirects + 1):
            check_url(current, pol)
            host = urlsplit(current).hostname or ""
            screen_host(host, pol, resolver=resolver)
            resp = await http.get(current)
            if resp.is_redirect:
                location = resp.headers.get("location")
                if not location:
                    raise SsrfError("bad_redirect", "redirect with no Location")
                target = str(resp.url.join(location))
                if not same_authority(current, target):
                    raise SsrfError(
                        "cross_authority_redirect",
                        f"redirect {current} -> {target} crosses the authority",
                    )
                current = target
                continue
            data = resp.content
            if len(data) > pol.max_bytes:
                raise SsrfError(
                    "response_too_large",
                    f"{len(data)} bytes exceeds cap {pol.max_bytes}",
                )
            return data
        raise SsrfError("too_many_redirects", f"exceeded {pol.max_redirects} redirects")
    finally:
        if owns:
            await http.aclose()


async def fetch_data_ref(
    data_ref: dict,
    *,
    policy: SsrfPolicy | None = None,
    resolver: Resolver | None = None,
    client: httpx.AsyncClient | None = None,
) -> bytes:
    """Fetch a ``data_refs[]`` entry's ``location`` under the SSRF guard.

    When the entry carries a ``content_hash`` (``sha256:<hex>``) the
    fetched bytes are verified against it; a mismatch raises
    :class:`DataRefHashMismatch` and the data MUST NOT be reported as
    verified (RFC-ACDP-0008 §4.9).
    """
    location = data_ref.get("location")
    if not location:
        raise SsrfError("no_location", "data_ref has no location to fetch")
    data = await fetch(location, policy=policy, resolver=resolver, client=client)
    expected = data_ref.get("content_hash")
    if expected:
        algo, _, hexdigest = expected.partition(":")
        if algo != "sha256":
            raise DataRefHashMismatch(f"unsupported content_hash algorithm: {algo!r}")
        actual = hashlib.sha256(data).hexdigest()
        if actual != hexdigest:
            raise DataRefHashMismatch(
                f"data_ref content_hash mismatch: expected {hexdigest[:16]}…, got {actual[:16]}…"
            )
    return data


__all__ = [
    "DataRefHashMismatch",
    "Resolver",
    "SsrfError",
    "SsrfPolicy",
    "check_url",
    "fetch",
    "fetch_data_ref",
    "ip_is_forbidden",
    "same_authority",
    "screen_host",
]
