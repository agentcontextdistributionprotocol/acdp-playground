# ACDP Playground Documentation

The **ACDP Playground** generates real Agent Context Distribution Protocol
(ACDP) traffic so the SDK (`acdp-rs`), the registry (`acdp-registry-rs`), and the
control plane (`acdp-control-plane`) can be exercised end-to-end. It spins up
agents, calls real LLMs, publishes signed context, streams events over SSE, and
forwards registry webhooks.

This is the **conformance and demonstration harness** for ACDP — not the protocol
itself, and not the SDK, registry, or control plane.

## Scope of these docs

These docs cover **only what is unique to the playground**: the scenario
catalog, the run lifecycle, the SSE event API, the agent abstractions, and the
thin `acdp_client` orchestration layer. Anything that belongs to another project
is **referenced, not re-explained** — the protocol rules live in the spec; the
cryptography, canonicalization, and SSRF classification live in the SDK; auth,
webhooks, and tenancy mechanics live in the registry and control plane.

See **[Related projects](#related-projects)** below for where each topic is
canonically documented.

## Documentation map

| Document | What it covers |
|----------|----------------|
| [Getting started](getting-started.md) | Install, smoke-test, run the stack, start your first run |
| [Architecture](architecture.md) | Components, request flow, the run lifecycle, the SSE bus |
| [Scenarios](scenarios.md) | The S1–S32 catalog, what each proves, and how to author one |
| [HTTP API](http-api.md) | Every route on the playground service |
| [Client SDK](client-sdk.md) | `acdp_client` — the async wrapper the playground drives the SDK through |
| [Agents](agents.md) | `BasePlaygroundAgent` and the LangChain / CrewAI / LangGraph adapters |
| [Configuration](configuration.md) | The playground's own environment variables |
| [Deployment](deployment.md) | Docker Compose, the full stack, and Railway |
| [Testing & conformance](testing-and-conformance.md) | The unit suite, smoke test, and live conformance probes |

## What ACDP is (in one paragraph)

ACDP lets autonomous agents **publish, derive, supersede, and discover signed
context** across federated registries. Each context carries a cryptographic
signature (Ed25519 or ECDSA-P256), a lineage identifier, and a derivation graph
(`derived_from`). Registries verify signatures, enforce visibility/tenancy, and
emit webhooks; a control plane issues bearer tokens, federates revocation, and
keeps an audit ledger. The playground makes all of this observable by running
named scenarios and streaming each protocol step to a client in real time.

The normative definitions live in the spec — start with
[RFC-ACDP-0001 (core)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md).

## Related projects

The playground is one repo in the ACDP family. Each sibling owns its own docs
(published under its own section on
[agentcontextdistributionprotocol.io](https://agentcontextdistributionprotocol.io)).
Reach for these when you need the canonical detail:

| Project | Repo | Owns the docs for |
|---------|------|-------------------|
| **Spec / RFCs** | [`agentcontextdistributionprotocol`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/tree/main/rfcs) | The protocol itself: context body, publish, retrieval, discovery, cross-registry, capabilities, security, extensions |
| **SDK** (`acdp-rs`) | [`acdp-rs`](https://github.com/agentcontextdistributionprotocol/acdp-rs/tree/main/docs) | Signing (Ed25519/P-256), JCS canonicalization, the SSRF policy, error taxonomy, the Python/Node bindings the playground imports |
| **Registry** | [`acdp-registry-rs`](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/tree/main/docs) | Registry HTTP API, authentication, multi-tenancy, webhooks, configuration, operations |
| **Control plane** | [`acdp-control-plane`](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/tree/main/docs) | Token issuance, introspection, revocation, policy, ingest, federation, CP configuration |
| **UI console** | [`acdp-ui-console`](https://github.com/agentcontextdistributionprotocol/acdp-ui-console) | The web UI that visualizes runs |

### Frequently-needed cross-references

- **How a context is signed / canonicalized** → [`acdp-rs` producing.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/producing.md) · [security.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md)
- **The error-envelope & error codes** → [`acdp-rs` errors.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/errors.md)
- **The SSRF policy the guard delegates to** → [`acdp-rs` security.md](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md) · [RFC-ACDP-0008 (security)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0008-security.md)
- **Token issuance / challenge flow** → [registry AUTHENTICATION.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/AUTHENTICATION.md) · [control-plane AUTH.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/AUTH.md)
- **Multi-tenancy rules** → [registry MULTI-TENANCY.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/MULTI-TENANCY.md) · [control-plane TENANCY.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/TENANCY.md)
- **Registry / CP configuration knobs** → [registry CONFIGURATION.md](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/CONFIGURATION.md) · [control-plane CONFIGURATION.md](https://github.com/agentcontextdistributionprotocol/acdp-control-plane/blob/main/docs/CONFIGURATION.md)

## Repo links

- **Project README:** [`../README.md`](../README.md)
- **Changelog:** [`../CHANGELOG.md`](../CHANGELOG.md)
- **Railway deploy:** [`../railway/DEPLOY.md`](../railway/DEPLOY.md)

> Changes to `docs/**` or `README.md` on `main` trigger a sync to the
> `acdp-website` repo (`.github/workflows/notify-website.yml`), which publishes
> this folder as the **/playground** section of the docs site. Keep these files
> in clean, self-contained Markdown.
