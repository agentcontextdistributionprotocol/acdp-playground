"""S16 — consumer-side SSRF guard on a ``data_refs[].location`` fetch.

A producer can put any URL in a context's ``data_refs[].location``. A
consumer that blindly follows it is an SSRF primitive: the URL might
resolve to the cloud metadata endpoint, a loopback admin port, or an
RFC-1918 service. RFC-ACDP-0008 §4.9 (cross-ref RFC-ACDP-0006 §7)
requires the consumer to screen the fetch.

The Rust SDK enforces this in its core ``RegistryClient`` — which the
playground's ``httpx`` client does not use — so the playground ships its
own guard in :mod:`acdp_client.safe_http`. This scenario exercises it
**fully offline** with an injected DNS resolver, mirroring the RFC's
``data-ref-ssrf-*`` conformance fixtures:

* IMDS (``169.254.169.254``) → blocked
* mixed answer set (one public + one private) → whole resolution rejected
* same-host cross-port redirect → refused
* ``http://`` location → refused

No registry, network, or LLM required.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from acdp_client.models import StepEvent
from acdp_client.safe_http import (
    SsrfError,
    SsrfPolicy,
    check_url,
    same_authority,
    screen_host,
)
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s16_dataref_ssrf",
    name="Consumer SSRF guard (data_refs)",
    description="A consumer following a data_refs[].location is screened for "
    "private/loopback/IMDS targets, mixed DNS answers, cross-port "
    "redirects, and non-https schemes (RFC-ACDP-0008 §4.9). Runs "
    "fully offline with an injected resolver.",
    registry_mode="single",
    agent_count=0,
    framework="langchain",
    default_inputs={},
)

# A deterministic stub resolver: maps the fixture hostnames to the DNS
# answer sets the RFC's data-ref-ssrf fixtures pin.
_DNS = {
    "data.attacker.example": ["203.0.113.10", "10.0.0.1"],  # mixed answer
    "imds.attacker.example": ["169.254.169.254"],
    "loopback.attacker.example": ["127.0.0.1"],
    "data.example.com": ["203.0.113.50"],  # legitimately public
}


def _resolver(host: str) -> list[str]:
    return _DNS.get(host, ["203.0.113.99"])


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    pol = SsrfPolicy.production()
    outcomes: dict[str, str] = {}

    async def note(title: str, preview: str) -> None:
        await events.put(
            StepEvent(
                type="scenario.note",
                run_id=spec.run_id,
                ts=datetime.now(timezone.utc).isoformat(),
                title=title,
                preview=preview,
            )
        )

    # 1. IMDS target — must be blocked before connecting.
    try:
        screen_host("imds.attacker.example", pol, resolver=_resolver)
        outcomes["imds"] = "NOT-BLOCKED"
    except SsrfError as e:
        outcomes["imds"] = f"blocked:{e.reason}"
    await note("IMDS data_ref", outcomes["imds"])

    # 2. Mixed answer set — one public + one private → reject the WHOLE set.
    try:
        screen_host("data.attacker.example", pol, resolver=_resolver)
        outcomes["mixed_answer"] = "NOT-BLOCKED"
    except SsrfError as e:
        outcomes["mixed_answer"] = f"blocked:{e.reason}"
    await note("mixed DNS answer", outcomes["mixed_answer"])

    # 3. Same-host cross-port redirect — refused; explicit :443 == default.
    cross_port = same_authority(
        "https://data.example.com/file", "https://data.example.com:8443/file"
    )
    same_port = same_authority("https://data.example.com/file", "https://data.example.com:443/file")
    outcomes["cross_port_redirect"] = "refused" if not cross_port and same_port else "WRONG"
    await note("cross-port redirect", outcomes["cross_port_redirect"])

    # 4. http:// location — refused without connecting.
    try:
        check_url("http://data.example.com/file", pol)
        outcomes["http_scheme"] = "NOT-BLOCKED"
    except SsrfError as e:
        outcomes["http_scheme"] = f"blocked:{e.reason}"
    await note("http scheme", outcomes["http_scheme"])

    # 5. A public https location passes the screen (then a real GET, which is
    #    expected to fail with a transport error offline — that's fine, the
    #    point is the screen let it through).
    try:
        screen_host("data.example.com", pol, resolver=_resolver)
        outcomes["public_screen"] = "passed"
    except SsrfError as e:  # pragma: no cover - shouldn't happen
        outcomes["public_screen"] = f"unexpected-block:{e.reason}"
    await note("public location screen", outcomes["public_screen"])

    ok = (
        outcomes["imds"].startswith("blocked")
        and outcomes["mixed_answer"].startswith("blocked")
        and outcomes["cross_port_redirect"] == "refused"
        and outcomes["http_scheme"].startswith("blocked")
        and outcomes["public_screen"] == "passed"
    )

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if ok else "failed",
        contexts=[],
        summary={"ssrf_guard": outcomes},
        error=None if ok else "S16 SSRF-guard assertions failed",
    )
