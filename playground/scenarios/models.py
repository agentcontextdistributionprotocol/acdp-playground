"""Scenario data model.

A :class:`ScenarioDef` is the static metadata; :class:`RunSpec` is the
per-invocation state (run_id, inputs, deterministic seed material);
:class:`RunResult` is the summary returned to the API caller.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from pydantic import BaseModel, Field

RegistryMode = Literal["single", "dual", "cross_org"]
Framework = Literal["langchain", "crewai", "langgraph", "mixed"]


class ScenarioDef(BaseModel):
    id: str
    name: str
    description: str
    registry_mode: RegistryMode = "single"
    agent_count: int = 1
    framework: Framework = "langchain"
    default_inputs: dict[str, Any] = Field(default_factory=dict)
    # populated by registry on discovery
    run: Callable[[RunSpec, Any], Awaitable[RunResult]] | None = None


class RunRequest(BaseModel):
    scenario_id: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    registry_mode: RegistryMode | None = None  # override default


class RunSpec(BaseModel):
    run_id: str
    scenario_id: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    registry_mode: RegistryMode = "single"

    def agent_seed(self, slug: str) -> bytes:
        """Deterministic 32-byte seed from run_id + slug.

        Same scenario + slug across runs produces a different identity
        each run (because run_id changes). Within one run, the same
        slug always yields the same key.
        """
        digest = hashlib.sha256(f"{self.run_id}:{slug}".encode()).digest()
        return digest


class LineageNode(BaseModel):
    ctx_id: str
    agent_id: str
    title: str
    context_type: str
    registry_authority: str
    step: int


class LineageEdge(BaseModel):
    src: str
    dst: str


class LineageGraph(BaseModel):
    nodes: list[LineageNode] = Field(default_factory=list)
    edges: list[LineageEdge] = Field(default_factory=list)


class RunResult(BaseModel):
    run_id: str
    scenario_id: str
    status: Literal["complete", "failed"] = "complete"
    contexts: list[str] = Field(default_factory=list)
    lineage_graph: LineageGraph | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


# Type alias for the runner signature (queue is loose to avoid circular import)
ScenarioFunc = Callable[[RunSpec, Any], Awaitable[RunResult]]
