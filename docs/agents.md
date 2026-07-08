# Agents

An **agent** owns one ACDP identity (a `Producer` + an `AcdpClient`), calls an
LLM, and publishes signed context — emitting an SSE `StepEvent` for every
protocol action. The base class lives in `playground/agents/base.py`; three
framework adapters wrap LangChain, CrewAI, and LangGraph.

## `BasePlaygroundAgent`

```python
BasePlaygroundAgent(
    producer,          # Ed25519 or P-256 signer (Rust SDK)
    client,            # AcdpClient bound to a registry
    events,            # asyncio.Queue[StepEvent]
    run_id,
    *,
    authority_map=None,   # dict[authority -> AcdpClient] for cross-registry resolve
    slug=None,            # identity tag, surfaced in metadata
)
```

Class attribute `framework` identifies the adapter (`"base"`, `"langchain"`,
`"crewai"`, `"langgraph"`); it is stamped into published metadata for
observability.

### Core operations

| Method | What it does |
|--------|--------------|
| `publish(task, llm_result)` | Builds the signed publish request via `producer.build_publish_request(...)`, POSTs it through `client.publish(...)` (forwarding `task.idempotency_key`), emits `acdp.publish`, returns `AgentOutput` |
| `supersede(previous_body_json, task, llm_result, *, expected_lineage_id=None)` | Carries the lineage forward + auto-increments the version via `build_supersede_request(...)`; optional `expected_lineage_id` is the concurrency guard |
| `retrieve(ctx_id)` | Cross-registry-aware retrieval via `client.resolve(ctx_id, authority_map)`; emits `acdp.retrieve` |
| `search(**filters)` | `client.search(...)`; emits `acdp.search` |
| `call_llm(prompt)` | Abstract — subclasses implement the LLM call |
| `run(task)` | The default agent loop (below) |

### The default `run(task)` loop

1. Emit `agent.started` with the task title.
2. **Grounding** — if `task.derived_from` is set, retrieve up to the first two
   referenced contexts and prepend them (with agent id + title) to the prompt.
3. **LLM** — if `task.override_response` is set (tests), use it; otherwise emit
   `llm.thinking` and call `call_llm(prompt)`.
4. **Publish** — call `publish(task, llm_result)` and return the `AgentOutput`.

### `AgentTask`

The unit of work an agent runs. Notable fields:

| Field | Purpose |
|-------|---------|
| `prompt`, `title` | LLM input and context title |
| `context_type` | e.g. `data_snapshot` (default), `analysis`, … |
| `visibility` | `public` (default), `restricted`, … |
| `domain`, `tags`, `audience`, `contributors` | Discovery + access metadata |
| `derived_from` | Parent ctx ids — establishes lineage edges and grounding |
| `data_refs`, `data_period`, `expires_at`, `schema_uri` | Extended body fields |
| `metadata` | Free-form; merged with framework/run/slug tags |
| `idempotency_key` | Forwarded verbatim to the registry |
| `override_response` | Bypass the LLM (deterministic tests) |
| `summary_chars` | Truncation budget for the summary |

`_publish_kwargs` omits empty fields to keep the content-hash preimage minimal
and JSON-encodes `metadata`, `data_refs`, and `data_period`.

### `AgentOutput`

Returned by `publish`/`run`: `ctx_id`, `lineage_id`, `version`, `title`,
`llm_response`, `content_hash` (taken from the signed request).

## Framework adapters

All three read the LLM provider from settings (`LLM_PROVIDER`, `LLM_MODEL`, and
the matching API key) and lazy-import their heavyweight dependencies so the base
install stays light.

> **Catalog usage.** Every scenario in the current catalog (S1–S32) uses
> `LangChainAgent` via `_factory.make_langchain_agent`; the CrewAI and
> LangGraph adapters exist as reference implementations (importable from their
> module paths — `playground.agents` only exports `LangChainAgent`) but no
> scenario instantiates them yet. Install them with the `multiagent` extra.

### `LangChainAgent` (`framework = "langchain"`)

The default. If no `llm` is passed, it builds one from settings via
`build_llm(...)`. `call_llm(prompt)` calls `llm.ainvoke(prompt)` and returns
`.content`.

### `CrewAIAgent` (`framework = "crewai"`)

Wraps CrewAI as a "crew of one" with configurable `role` / `goal` / `backstory`.
The agent is lazy-built on first call. Because CrewAI's execution is synchronous,
`call_llm` offloads `task.execute_sync()` to a thread via `asyncio.to_thread`.

### `LangGraphAgent` (`framework = "langgraph"`)

A minimal two-node graph — `think` (drafts an outline) → `respond` (calls the
LLM) → `END`. State is a `TypedDict` of `prompt` / `draft` / `answer`. The
compiled app is cached; `call_llm` invokes it and returns the `answer`.

## The LLM factory

`build_llm(provider, model, *, api_key="")`:

| `provider` | Result |
|------------|--------|
| `mock` | `_MockLLM` — echoes the first line of the prompt (deterministic, no key) |
| `openai` | `langchain_openai.ChatOpenAI(model, api_key)` |
| `anthropic` | `langchain_anthropic.ChatAnthropic(model, api_key)` |

Unknown providers raise `ValueError`. Set `LLM_PROVIDER=mock` for offline smoke
and CI runs.

> When building real LLM applications on top of ACDP, prefer the latest Claude
> models (e.g. `claude-opus-4-8`, `claude-sonnet-4-6`). The playground's
> `anthropic` provider passes `LLM_MODEL` straight through to
> `langchain-anthropic`.
