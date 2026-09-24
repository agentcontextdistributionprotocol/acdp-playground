"""Idempotent-publish contract (registry acdp-registry-rs #24).

The client side of idempotency is simply: send the ``Idempotency-Key`` header
verbatim, never pre-validate or mangle it. The *replay* semantics live in the
registry; here we use a mock transport that emulates them so we can pin the
client's behaviour offline:

* a repeated key returns the first response (one ``ctx_id``, never two);
* keys at the 1- and 256-char bounds are forwarded unchanged;
* an out-of-range (257-char) key is still forwarded — the client does not
  pre-reject it; the registry is what treats it as absent.
"""

from __future__ import annotations

import itertools

import httpx

from acdp_client import AcdpClient
from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id


def _idempotent_registry(captured: list[str | None]):
    """A mock registry that replays a stored response per Idempotency-Key.

    Records every inbound key in ``captured`` (in order) and mints a fresh
    ``ctx_id`` only for a key it hasn't seen; a repeat (or an absent key seen
    twice) of a stored key replays the same ``ctx_id``.
    """
    counter = itertools.count(1)
    by_key: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        key = request.headers.get("idempotency-key")
        captured.append(key)
        if key is not None and key in by_key:
            ctx_id = by_key[key]  # replay
        else:
            n = next(counter)
            ctx_id = synthetic_ctx_id("reg.test", f"idempotency-{n}")
            if key is not None:
                by_key[key] = ctx_id
        return httpx.Response(
            200,
            json={
                "ctx_id": ctx_id,
                "lineage_id": synthetic_lineage_id("idempotency"),
                "version": 1,
                "created_at": "2026-06-03T00:00:00Z",
                "status": "active",
            },
        )

    return handler


def _client(handler) -> AcdpClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://reg.test")
    return AcdpClient("http://reg.test", http=http)


async def test_duplicate_key_replays_single_context():
    captured: list[str | None] = []
    client = _client(_idempotent_registry(captured))
    first = await client.publish("{}", idempotency_key="dup-key")
    second = await client.publish("{}", idempotency_key="dup-key")
    assert first.ctx_id == second.ctx_id  # one context, replayed
    assert captured == ["dup-key", "dup-key"]  # header forwarded both times


async def test_distinct_keys_produce_distinct_contexts():
    captured: list[str | None] = []
    client = _client(_idempotent_registry(captured))
    a = await client.publish("{}", idempotency_key="key-a")
    b = await client.publish("{}", idempotency_key="key-b")
    assert a.ctx_id != b.ctx_id


async def test_boundary_length_keys_forwarded_verbatim():
    captured: list[str | None] = []
    client = _client(_idempotent_registry(captured))
    one = "x"  # 1 char — lower bound
    full = "k" * 256  # 256 chars — upper bound
    await client.publish("{}", idempotency_key=one)
    await client.publish("{}", idempotency_key=full)
    assert captured == [one, full]  # sent unchanged, not pre-validated


async def test_out_of_range_key_not_pre_rejected():
    """A 257-char key is over the registry's accepted range, but the client
    forwards it as-is; treating it as absent is the registry's job (#24)."""
    captured: list[str | None] = []
    client = _client(_idempotent_registry(captured))
    too_long = "z" * 257
    await client.publish("{}", idempotency_key=too_long)
    assert captured == [too_long]  # client did not raise or truncate


async def test_no_key_sends_no_header():
    captured: list[str | None] = []
    client = _client(_idempotent_registry(captured))
    await client.publish("{}")
    assert captured == [None]  # absent → header omitted entirely
