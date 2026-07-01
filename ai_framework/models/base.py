"""Pluggable LLM backend interface.

A backend turns the current run state into either an **action** (reasoning + tool calls)
or, after tool results are in, the **next plan** (log-driven planning, §2.2 step 4).
Swapping backends must not change how the agent loop is written.
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn


class ActResponse(BaseModel):
    """The assistant's reason + act segment for one turn."""

    reasoning: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    done: bool = False


class Backend(Protocol):
    """Reasoning supply. ``act`` proposes the next action; ``plan`` reflects on results."""

    name: str

    def act(
        self,
        system: str,
        transcript: list[Turn],
        config: RunConfig,
        tools: list[dict[str, Any]],
    ) -> ActResponse:
        ...

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        ...
