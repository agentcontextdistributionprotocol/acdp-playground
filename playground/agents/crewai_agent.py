"""CrewAI-backed agent (single-agent "crew of one" wrapper).

CrewAI is heavy and optional; the import is lazy so scenarios that
don't use this framework can run without it installed.
"""

from __future__ import annotations

from typing import Any

from playground.agents.base import BasePlaygroundAgent
from playground.config import get_settings


class CrewAIAgent(BasePlaygroundAgent):
    framework = "crewai"

    def __init__(
        self,
        *args: Any,
        role: str = "Research analyst",
        goal: str = "Produce concise, sourced summaries",
        backstory: str = "You are a careful analyst writing for an executive audience.",
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)
        self._role = role
        self._goal = goal
        self._backstory = backstory
        self._agent = None

    def _build_agent(self) -> Any:
        if self._agent is not None:
            return self._agent
        from crewai import Agent  # type: ignore

        s = get_settings()
        llm = None
        if s.llm_provider == "openai":
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(model=s.llm_model, api_key=s.openai_api_key or None)
        elif s.llm_provider == "anthropic":
            from langchain_anthropic import ChatAnthropic

            llm = ChatAnthropic(model=s.llm_model, api_key=s.anthropic_api_key or None)
        self._agent = Agent(
            role=self._role,
            goal=self._goal,
            backstory=self._backstory,
            llm=llm,
            allow_delegation=False,
        )
        return self._agent

    async def call_llm(self, prompt: str) -> str:
        import asyncio

        from crewai import Task  # type: ignore

        agent = self._build_agent()
        task = Task(description=prompt, agent=agent, expected_output="A concise summary.")

        # CrewAI is sync; offload to a thread.
        def _run() -> str:
            return (
                str(task.execute_sync())
                if hasattr(task, "execute_sync")
                else str(agent.execute_task(task))
            )

        return await asyncio.to_thread(_run)
