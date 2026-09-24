"""S34 — embedded data-ref content integrity (RFC-ACDP-0002 §6.3/§6.6).

A ``data_refs[]`` entry carries its payload one of two ways: by
``location`` (a URI the consumer fetches later) or ``embedded`` (the bytes
inline). Every scenario before this one publishes only the first form, so
the whole embedded branch — and the ``embedded.content_hash`` obligation
the spec puts on it — had no coverage anywhere in this repo.

Check 8 (§6.6) scopes the *publish-time* integrity obligation to
``embedded.content_hash`` and nothing else: when present it MUST equal the
SHA-256 of the **decoded** ``embedded.content`` bytes. The decoded form is
encoding-specific — ``json`` hashes the JCS canonical bytes, ``utf8`` the
raw UTF-8 bytes of the string, ``base64`` the base64-decoded bytes — so the
same visible payload has three different preimages and a producer that
picks the wrong one is refused.

Four conformance stories, all pinned offline:

1. **Every encoding hashes its own decoded form.** One ref per encoding
   with a correctly computed ``embedded.content_hash`` builds, signs and
   verifies, both as a wire ``PublishRequest`` and as the ``body`` a
   registry would serve back. Declaring the ``json`` preimage of a
   ``utf8`` string — a different digest over the same visible text —
   fails closed.
2. **``embedded.content_hash`` is not ``DataRef.content_hash``.** They are
   independent fields (§6.1 vs §6.3) and a ref MAY carry both over the
   same decoded bytes. The run proves the independence with *one* digest
   in *two* slots: a foreign digest in the root field, with a correct
   ``embedded.content_hash`` beside it, is **accepted** — §6.6 makes the
   root check a registry MAY, never a MUST, and SDK 0.14.1 reverted the
   undocumented 0.14.0 fallback that had briefly enforced it. The same
   foreign digest moved into ``embedded.content_hash``, with a correct
   root field beside it, is **rejected**. A scenario that conflated the
   two fields would report both cases identically.
3. **Absent is legal, explicit ``null`` is not.** The field is optional,
   so a ref with no ``embedded.content_hash`` verifies. ``EmbeddedContent``
   is ``deny_unknown_fields`` with a ``de_present`` deserializer on that
   member (``acdp-rs/crates/acdp-types/src/data_ref.rs:316-332``), so an
   explicit ``null`` is a *deserialization* failure, not a verification
   verdict — a distinction invisible from Python unless the run asserts on
   the SDK's own wording.
4. **Tampering fails closed at two different layers.** Flipping one byte
   of already-signed embedded content breaks the body-level
   ``content_hash`` on the publish-request path, and — on the retrieval
   path, where ``validate_body`` runs Check 8 *before* the signature —
   surfaces as the data-ref-level ``embedded.content_hash mismatch``. Both
   wordings are asserted, because "something raised" is not the same claim
   as "the embedded-hash check ran".

The live half publishes the embedded refs to registry-a, retrieves and
re-verifies the served body, then supersedes to confirm the embedded
payloads and their hashes are carried forward byte-exactly. Registry
acceptance of §6.3 is version-dependent, so the live half degrades
gracefully; the deterministic core above is the required proof.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from acdp import AcdpCanonicalizer, AcdpVerifier

from acdp_client import AcdpHTTPError
from acdp_client.identifiers import synthetic_ctx_id, synthetic_lineage_id
from acdp_client.models import StepEvent
from playground.config import get_settings
from playground.scenarios._factory import AgentBundle, producer_for
from playground.scenarios._receipts import synthesize_retrieval_body
from playground.scenarios._sdk_guard import expect_rejection, run_guarded
from playground.scenarios.models import (
    LineageEdge,
    LineageGraph,
    LineageNode,
    RunResult,
    RunSpec,
    ScenarioDef,
)

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s34_embedded_content",
    name="Embedded Content Integrity",
    description="A data_refs[].embedded payload's own content_hash (RFC-ACDP-0002 "
    "§6.3/§6.6 Check 8) is verified over the decoded bytes — JCS form for "
    "json, raw UTF-8 for utf8, decoded bytes for base64. It is independent "
    "of the DataRef-root content_hash (§6.1): one foreign digest is accepted "
    "in the root slot and rejected in the embedded slot. Absent is legal, "
    "explicit null is a deserialization failure, and tampered content fails "
    "closed at both the body and data-ref layers.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={"topic": "inline sensor snapshot"},
)

#: Sentinel for "omit ``content_hash`` entirely", which is a *different* wire
#: shape from ``"content_hash": null`` — the whole point of story 3.
_ABSENT: Any = object()

#: The ACDP protocol version stamped on every body this scenario builds.
#: Pinned rather than defaulted so the run stays byte-reproducible when the
#: SDK's own ``ACDP_VERSION`` default moves; it matches S33, the most recent
#: protocol generation the catalog models.
_ACDP_VERSION = "0.5.0"

#: A fixed registry-assigned timestamp for the synthesized retrieval body.
#: Canonical millisecond RFC 3339 UTC, as ``synthesize_retrieval_body`` requires.
_SERVED_AT = "2026-01-01T00:00:00.000Z"


def _sha256_hash(payload: bytes) -> str:
    """``"sha256:<hex>"`` over raw bytes — the ``utf8``/``base64`` preimage.

    No canonicalization is involved for these two encodings: the decoded form
    *is* the byte string. The ``json`` preimage goes through the SDK
    canonicalizer instead (:func:`_json_hash`), never through here.
    """
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _json_hash(value: Any) -> str:
    """``"sha256:<hex>"`` over the JCS canonical form — the ``json`` preimage.

    Delegated to the SDK canonicalizer (CLAUDE.md): RFC 8785 canonicalization
    is a protocol primitive and the playground never grows a second one.
    """
    return AcdpCanonicalizer.content_hash(json.dumps(value))


def _ref(
    ref_type: str,
    encoding: str,
    content: Any,
    *,
    embedded_hash: Any = _ABSENT,
    root_hash: str | None = None,
    fmt: str | None = None,
) -> dict[str, Any]:
    """Build one wire ``data_refs[]`` entry in ``embedded`` form.

    ``embedded_hash`` left at :data:`_ABSENT` omits the member; passing
    ``None`` emits an explicit JSON ``null``. ``root_hash`` populates the
    *enclosing* ``DataRef.content_hash`` (§6.1), which is a different field.
    """
    embedded: dict[str, Any] = {"encoding": encoding, "content": content}
    if embedded_hash is not _ABSENT:
        embedded["content_hash"] = embedded_hash
    ref: dict[str, Any] = {"type": ref_type, "embedded": embedded}
    if fmt is not None:
        ref["format"] = fmt
    if root_hash is not None:
        ref["content_hash"] = root_hash
    return ref


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    bundle = AgentBundle(settings, spec.run_id)
    authority = settings.registry_a_authority
    topic = spec.inputs.get("topic", SCENARIO.default_inputs["topic"])

    try:
        producer = producer_for(spec, "embedded-producer", authority, method="did:key")

        def build(title: str, refs: list[dict[str, Any]], summary: str) -> str:
            return producer.build_publish_request(
                title=title,
                context_type="data_snapshot",
                visibility="public",
                summary=summary,
                tags=["embedded"],
                data_refs=json.dumps(refs),
                acdp_version=_ACDP_VERSION,
            )

        # ── The three encodings and their three distinct preimages. ───────
        json_payload = {"station": topic, "unit": "celsius", "readings": [21.5, 21.7, 22.0]}
        # Non-ASCII on purpose: the utf8 preimage is the decoded *bytes*, so a
        # hash over code points or over the JSON-escaped form would differ.
        utf8_payload = "inlet probe — 21.5 °C, drifting"
        binary_payload = bytes(range(32))
        b64_payload = base64.b64encode(binary_payload).decode()

        json_hash = _json_hash(json_payload)
        utf8_hash = _sha256_hash(utf8_payload.encode())
        b64_hash = _sha256_hash(binary_payload)

        # The same visible text hashed as if it were `json` — the canonical
        # form of a JSON *string* includes its quotes and escapes, so this is
        # a genuinely different digest over the same characters.
        utf8_as_json_hash = _json_hash(utf8_payload)
        encoding_preimages_distinct = utf8_as_json_hash != utf8_hash

        honest_refs = [
            _ref(
                "primary_result",
                "json",
                json_payload,
                embedded_hash=json_hash,
                fmt="application/json",
            ),
            _ref("supporting_info", "utf8", utf8_payload, embedded_hash=utf8_hash),
            _ref("raw_data", "base64", b64_payload, embedded_hash=b64_hash),
        ]
        honest_raw = build(
            topic,
            honest_refs,
            "One embedded ref per encoding, each with a correct embedded.content_hash.",
        )
        honest_verified = AcdpVerifier.verify_publish_request_offline(honest_raw)

        # The same content as a registry would serve it back. `validate_body`
        # runs Check 8 on the retrieval side too, so this is the second,
        # independent place the honest hashes have to hold up.
        offline_ctx = synthetic_ctx_id(authority, f"{spec.run_id}:s34-embedded")
        served_body = synthesize_retrieval_body(
            honest_raw,
            ctx_id=offline_ctx,
            lineage_id=synthetic_lineage_id(f"{spec.run_id}:s34-embedded"),
            origin_registry=authority,
            created_at=_SERVED_AT,
        )
        served_verified = AcdpVerifier.verify_body_offline(json.dumps(served_body))

        # ── Wrong preimage for the encoding: utf8 declared with its JCS form.
        utf8_wrong_preimage_rejected, utf8_wrong_why = expect_rejection(
            lambda: build(
                f"{topic} (utf8 with a json preimage)",
                [_ref("supporting_info", "utf8", utf8_payload, embedded_hash=utf8_as_json_hash)],
                "A utf8 ref declaring the JCS digest of the same text.",
            )
        )
        utf8_wrong_preimage_rejected = (
            utf8_wrong_preimage_rejected and "embedded.content_hash mismatch" in utf8_wrong_why
        )

        # ── §6.1 root vs §6.3 embedded: one digest, two slots. ────────────
        # `utf8_hash` is a real digest of a real payload, and unrelated to the
        # json ref's decoded bytes. In the root slot it is ignored (§6.6 makes
        # the root check a registry MAY); in the embedded slot it is fatal.
        foreign_root_raw, foreign_root_exc = run_guarded(
            lambda: build(
                f"{topic} (foreign root content_hash)",
                [
                    _ref(
                        "primary_result",
                        "json",
                        json_payload,
                        embedded_hash=json_hash,
                        root_hash=utf8_hash,
                        fmt="application/json",
                    )
                ],
                "Root DataRef.content_hash disagrees; embedded.content_hash is correct.",
            )
        )
        foreign_root_accepted = foreign_root_exc is None and bool(
            AcdpVerifier.verify_publish_request_offline(foreign_root_raw)
        )

        foreign_embedded_rejected, foreign_embedded_why = expect_rejection(
            lambda: build(
                f"{topic} (foreign embedded content_hash)",
                [
                    _ref(
                        "primary_result",
                        "json",
                        json_payload,
                        embedded_hash=utf8_hash,
                        root_hash=json_hash,
                        fmt="application/json",
                    )
                ],
                "Root DataRef.content_hash is correct; embedded.content_hash is not.",
            )
        )
        foreign_embedded_rejected = (
            foreign_embedded_rejected
            and "embedded.content_hash mismatch" in foreign_embedded_why
            and utf8_hash in foreign_embedded_why
        )
        root_embedded_independent = foreign_root_accepted and foreign_embedded_rejected

        # Both fields present, both correct over the same decoded bytes — the
        # shape §6.3 explicitly permits.
        both_raw = build(
            f"{topic} (root + embedded content_hash)",
            [
                _ref(
                    "primary_result",
                    "json",
                    json_payload,
                    embedded_hash=json_hash,
                    root_hash=json_hash,
                    fmt="application/json",
                )
            ],
            "Both content_hash fields present and both correct.",
        )
        both_hashes_verified = bool(AcdpVerifier.verify_publish_request_offline(both_raw))

        # ── Absent is legal; explicit null is a deserialization failure. ──
        absent_raw = build(
            f"{topic} (no embedded content_hash)",
            [_ref("primary_result", "json", json_payload, fmt="application/json")],
            "embedded.content_hash omitted — optional, so Check 8 has nothing to do.",
        )
        absent_verified = bool(AcdpVerifier.verify_publish_request_offline(absent_raw))

        # Injected into an already-signed request, so the rejection is the
        # wire deserializer's (`de_present`), not the builder's.
        null_wire = json.loads(absent_raw)
        null_wire["data_refs"][0]["embedded"]["content_hash"] = None
        explicit_null_rejected, explicit_null_why = expect_rejection(
            lambda: AcdpVerifier.verify_publish_request_offline(json.dumps(null_wire))
        )
        explicit_null_rejected = (
            explicit_null_rejected and "invalid type: null" in explicit_null_why
        )

        # ── Tampering fails closed at two layers, with two wordings. ──────
        tampered_request = json.loads(honest_raw)
        tampered_request["data_refs"][0]["embedded"]["content"]["unit"] = "fahrenheit"
        request_tamper_rejected, request_tamper_why = expect_rejection(
            lambda: AcdpVerifier.verify_publish_request_offline(json.dumps(tampered_request))
        )
        # Assert the *body-level* wording specifically. "content_hash mismatch"
        # alone would be satisfied by the embedded wording too, since the latter
        # contains it as a substring — so the check would silently stop
        # separating the two layers if a future SDK ever ran Check 8 from this
        # entry point. Requiring the absence of the "embedded." qualifier is
        # what makes this assertion say what the docstring claims.
        request_tamper_rejected = (
            request_tamper_rejected
            and "content_hash mismatch" in request_tamper_why
            and "embedded." not in request_tamper_why
        )

        tampered_body = json.loads(json.dumps(served_body))
        tampered_body["data_refs"][0]["embedded"]["content"]["unit"] = "fahrenheit"
        body_tamper_rejected, body_tamper_why = expect_rejection(
            lambda: AcdpVerifier.verify_body_offline(json.dumps(tampered_body))
        )
        # The retrieval path runs Check 8 *before* the signature, so the
        # verdict names the data ref — proof the embedded check actually ran
        # rather than the body hash catching it first.
        body_tamper_rejected = body_tamper_rejected and (
            "embedded.content_hash mismatch" in body_tamper_why
        )

        offline_core_ok = all(
            (
                bool(honest_verified),
                bool(served_verified),
                encoding_preimages_distinct,
                utf8_wrong_preimage_rejected,
                root_embedded_independent,
                both_hashes_verified,
                absent_verified,
                explicit_null_rejected,
                request_tamper_rejected,
                body_tamper_rejected,
            )
        )

        await events.put(
            StepEvent(
                type="acdp.verify",
                run_id=spec.run_id,
                ts=datetime.now(UTC).isoformat(),
                agent_id=producer.agent_did,
                ctx_id=offline_ctx,
                title="Embedded content_hash verified over decoded bytes (Check 8)",
                preview=f"encodings=json/utf8/base64 root_vs_embedded_independent="
                f"{root_embedded_independent} null_rejected={explicit_null_rejected} "
                f"tamper_rejected={request_tamper_rejected and body_tamper_rejected}",
            )
        )

        # ── Live: publish embedded, retrieve, supersede-carry. ────────────
        client = bundle.anonymous_client("a")
        ctx1: str | None = None
        ctx2: str | None = None
        registry_outcome = "skipped"
        live_refs_round_trip = False
        live_body_verified = False
        live_carry_forward = False
        try:
            resp1 = await client.publish(honest_raw)
            ctx1 = resp1.ctx_id
            await events.put(
                StepEvent(
                    type="acdp.publish",
                    run_id=spec.run_id,
                    ts=datetime.now(UTC).isoformat(),
                    agent_id=producer.agent_did,
                    ctx_id=ctx1,
                    title=topic,
                    preview="3 embedded data_refs (json, utf8, base64)",
                )
            )

            v1_raw = await client.retrieve_raw(ctx1)
            v1_body_json = json.dumps(v1_raw["body"])
            live_body_verified = bool(AcdpVerifier.verify_body_offline(v1_body_json))
            # Byte-exact: the embedded payloads *and* their declared hashes
            # survive the registry round trip unchanged.
            live_refs_round_trip = v1_raw["body"].get("data_refs") == honest_refs

            supersede = producer.build_supersede_request(
                v1_body_json,
                title=f"{topic} (v2, embedded refs carried forward)",
                summary="Supersede with no data_refs param — must inherit v1's embedded refs.",
                acdp_version=_ACDP_VERSION,
            )
            resp2 = await client.publish(supersede)
            ctx2 = resp2.ctx_id
            v2_raw = await client.retrieve_raw(ctx2)
            live_carry_forward = v2_raw["body"].get("data_refs") == honest_refs and bool(
                AcdpVerifier.verify_body_offline(json.dumps(v2_raw["body"]))
            )

            await events.put(
                StepEvent(
                    type="acdp.verify",
                    run_id=spec.run_id,
                    ts=datetime.now(UTC).isoformat(),
                    agent_id=producer.agent_did,
                    ctx_id=ctx2,
                    title="Embedded refs round-tripped and carried forward on supersede",
                    preview=f"round_trip={live_refs_round_trip} carry_forward={live_carry_forward}",
                )
            )
            registry_outcome = "published_2"
        except AcdpHTTPError as e:
            registry_outcome = f"http_{e.status}:{e.code}"
            log.warning("S34 registry round-trip failed: %s", e)
        except Exception as e:  # noqa: BLE001 — no registry: degrade
            registry_outcome = f"unreachable:{type(e).__name__}"
            log.warning("S34 registry round-trip unreachable: %s", e)

        live_ok = live_body_verified and live_refs_round_trip and live_carry_forward
        degraded = not live_ok

        nodes = [
            LineageNode(
                ctx_id=c,
                agent_id=producer.agent_did,
                title=t,
                context_type="data_snapshot",
                registry_authority=authority,
                step=i,
            )
            for i, (c, t) in enumerate(
                (
                    (ctx1, topic),
                    (ctx2, f"{topic} (v2, embedded refs carried forward)"),
                ),
                start=1,
            )
            if c
        ]
        edges = [LineageEdge(src=ctx1, dst=ctx2)] if ctx1 and ctx2 else []

        summary = {
            "encodings_verified": ["json", "utf8", "base64"],
            "embedded_refs_verified": bool(honest_verified),
            "served_body_verified": bool(served_verified),
            "encoding_preimages_distinct": encoding_preimages_distinct,
            "utf8_wrong_preimage_rejected": utf8_wrong_preimage_rejected,
            "foreign_root_hash_accepted": foreign_root_accepted,
            "foreign_embedded_hash_rejected": foreign_embedded_rejected,
            "root_embedded_independent": root_embedded_independent,
            "both_hashes_verified": both_hashes_verified,
            "absent_content_hash_verified": absent_verified,
            "explicit_null_rejected": explicit_null_rejected,
            "request_tamper_rejected": request_tamper_rejected,
            "served_body_tamper_rejected": body_tamper_rejected,
            "offline_core_ok": offline_core_ok,
            "registry_round_trip": registry_outcome,
            "live_body_verified": live_body_verified,
            "live_refs_round_trip": live_refs_round_trip,
            "live_carry_forward": live_carry_forward,
        }
        if degraded:
            summary["degraded"] = True

        return RunResult(
            run_id=spec.run_id,
            scenario_id=SCENARIO.id,
            status="complete" if offline_core_ok else "failed",
            contexts=[c for c in (ctx1, ctx2) if c],
            lineage_graph=LineageGraph(nodes=nodes, edges=edges),
            summary=summary,
            error=None if offline_core_ok else "embedded content_hash core failed verification",
        )
    finally:
        await bundle.aclose()
