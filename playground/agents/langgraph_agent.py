"""LangGraph-backed agent.

Builds a minimal two-node graph (think -> respond). LangGraph is
imported lazily so scenarios that don't use this framework can run
without it installed.
"""

from __future__ import annotations

from typing import Any

from playground.agents.base import BasePlaygroundAgent, llm_for_settings, response_text


class LangGraphAgent(BasePlaygroundAgent):
    framework = "langgraph"

    def __init__(self, *args: Any, llm: Any = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._llm = llm
        self._app: Any | None = None

    def _build_app(self) -> Any:
        if self._app is not None:
            return self._app

        from langgraph.graph import END, StateGraph  # type: ignore
        from typing_extensions import TypedDict  # type: ignore

        llm = self._llm if self._llm is not None else llm_for_settings()

        class State(TypedDict):
            prompt: str
            draft: str
            answer: str

        async def think(state: State) -> dict[str, str]:
            return {
                "draft": f"Outline:\n- key risk\n- opportunity\n- recommendation\n\n{state['prompt']}"
            }

        async def respond(state: State) -> dict[str, str]:
            resp = await llm.ainvoke(state["draft"])
            return {"answer": response_text(resp)}

        graph = StateGraph(State)
        graph.add_node("think", think)
        graph.add_node("respond", respond)
        graph.set_entry_point("think")
        graph.add_edge("think", "respond")
        graph.add_edge("respond", END)
        self._app = graph.compile()
        return self._app

    async def call_llm(self, prompt: str) -> str:
        app = self._build_app()
        result = await app.ainvoke({"prompt": prompt, "draft": "", "answer": ""})
        return result.get("answer", "")
