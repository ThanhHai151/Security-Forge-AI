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


def normalize_usage(usage: Any, *, anthropic: bool = False) -> dict[str, int] | None:
    """Map a provider ``usage`` block to ``{prompt_tokens, completion_tokens, total_tokens}``.

    OpenAI-shaped responses report ``prompt_tokens``/``completion_tokens``/``total_tokens``;
    Anthropic reports ``input_tokens``/``output_tokens``. Returns ``None`` when no usage is
    present so callers can record a call with zero tokens rather than crash. Backends stash the
    result on ``self.last_usage`` for the RouterBackend to feed the quota tracker.
    """
    if not isinstance(usage, dict):
        return None
    if anthropic:
        prompt = int(usage.get("input_tokens") or 0)
        completion = int(usage.get("output_tokens") or 0)
        total = prompt + completion
    else:
        prompt = int(usage.get("prompt_tokens") or 0)
        completion = int(usage.get("completion_tokens") or 0)
        total = int(usage.get("total_tokens") or 0) or (prompt + completion)
    return {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": total}


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
