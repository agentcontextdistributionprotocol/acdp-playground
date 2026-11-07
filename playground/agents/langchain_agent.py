"""LangChain-backed agent.

Defaults to OpenAI per the playground's settings; can run against
Anthropic by setting ``LLM_PROVIDER=anthropic``. Falls through to the
deterministic mock when ``LLM_PROVIDER=mock``.
"""

from __future__ import annotations

from typing import Any

from playground.agents.base import BasePlaygroundAgent, llm_for_settings, response_text


class LangChainAgent(BasePlaygroundAgent):
    framework = "langchain"

    def __init__(self, *args: Any, llm: Any = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.llm = llm if llm is not None else llm_for_settings()

    async def call_llm(self, prompt: str) -> str:
        resp = await self.llm.ainvoke(prompt)
        return response_text(resp)
