"""Agents must turn every chat-model response shape into plain text.

LangChain's Anthropic client returns ``AIMessage.content`` as a list of
content blocks, not a string. Before the fix the agents passed that list
straight to the publish path (``llm_result[: task.summary_chars]`` and the
SSE preview), which crashed every Anthropic-backed run.

The core cases use duck-typed messages so they run without the optional
``llm`` extra (CI installs only ``dev``); the LangChain/LangGraph cases
skip when those packages are absent.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest

from playground.agents.langchain_agent import LangChainAgent
from playground.config import get_settings

ANTHROPIC_BLOCKS = [
    {"type": "thinking", "thinking": "internal", "signature": "sig"},
    {"type": "text", "text": "Key risk: margin. "},
    {"type": "tool_use", "id": "t1", "name": "lookup", "input": {}},
    {"type": "text", "text": "Recommendation: hedge."},
]
EXPECTED = "Key risk: margin. Recommendation: hedge."


class _Msg:
    def __init__(self, content: Any):
        self.content = content


class _FakeChatModel:
    def __init__(self, message: Any):
        self.message = message
        self.prompts: list[str] = []

    async def ainvoke(self, prompt: str) -> Any:
        self.prompts.append(prompt)
        return self.message


@pytest.mark.parametrize(
    ("resp", "expected"),
    [
        (_Msg("plain openai text"), "plain openai text"),
        (_Msg(ANTHROPIC_BLOCKS), EXPECTED),
        (_Msg(["a", {"type": "text", "text": "b"}]), "ab"),
        (_Msg([]), ""),
        ("bare string", "bare string"),
    ],
)
def test_response_text_normalises_every_shape(resp: Any, expected: str) -> None:
    from playground.agents.base import response_text

    assert response_text(resp) == expected


def test_response_text_matches_langchain_text_property() -> None:
    messages = pytest.importorskip("langchain_core.messages")
    from playground.agents.base import response_text

    msg = messages.AIMessage(content=ANTHROPIC_BLOCKS)
    assert response_text(msg) == msg.text == EXPECTED


async def test_langchain_agent_returns_text_for_anthropic_blocks() -> None:
    llm = _FakeChatModel(_Msg(ANTHROPIC_BLOCKS))
    # call_llm only touches the LLM, so identity and transport can be stubs.
    agent = LangChainAgent(None, None, asyncio.Queue(), "run-test", llm=llm)
    out = await agent.call_llm("assess the quarter")
    assert out == EXPECTED


@pytest.fixture
def anthropic_provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeChatModel]:
    """Select LLM_PROVIDER=anthropic and swap ChatAnthropic for a fake."""
    anthropic = pytest.importorskip("langchain_anthropic")
    fake = _FakeChatModel(_Msg(ANTHROPIC_BLOCKS))
    monkeypatch.setattr(anthropic, "ChatAnthropic", lambda **_: fake)
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test")
    get_settings.cache_clear()
    yield fake
    get_settings.cache_clear()


async def test_langgraph_agent_returns_text_for_anthropic_blocks(
    anthropic_provider: _FakeChatModel,
) -> None:
    pytest.importorskip("langgraph")
    from playground.agents.langgraph_agent import LangGraphAgent

    agent = LangGraphAgent(None, None, asyncio.Queue(), "run-test")
    out = await agent.call_llm("assess the quarter")
    assert out == EXPECTED
    assert "assess the quarter" in anthropic_provider.prompts[0]


async def test_langchain_agent_settings_path_returns_text(
    anthropic_provider: _FakeChatModel,
) -> None:
    agent = LangChainAgent(None, None, asyncio.Queue(), "run-test")
    assert await agent.call_llm("assess the quarter") == EXPECTED
