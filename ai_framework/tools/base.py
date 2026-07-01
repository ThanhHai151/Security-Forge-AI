"""Tool protocol, execution context, and registry.

A tool is a named, schema-described, runnable action that returns a **log** (a string).
The registry holds tools, emits their schemas for the system prompt, and executes a
``ToolCall`` into a ``ToolResult`` — catching errors so a misbehaving tool degrades to a
failed result instead of crashing the loop. See ``docs/HERMES_INTEGRATION_STEPS.md`` Step 2.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from ai_framework.agent.contracts import ToolCall, ToolResult


class ToolContext(BaseModel):
    """What a tool is allowed to know at execution time (the safety surface)."""

    authorized_targets: set[str] = set()


@runtime_checkable
class Tool(Protocol):
    """A runnable action. Implementations return the log string from ``run``."""

    name: str
    description: str

    @property
    def json_schema(self) -> dict[str, Any]:
        """JSON Schema for this tool's ``arguments`` object."""
        ...

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        """Execute and return the log. Raise on failure; the registry records it."""
        ...


class ToolRegistry:
    """Holds tools, exposes their schemas, and executes calls safely."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def schemas(self) -> list[dict[str, Any]]:
        """Schemas for the system prompt / backend tool declarations."""
        return [
            {"name": t.name, "description": t.description, "input_schema": t.json_schema}
            for t in self._tools.values()
        ]

    def execute(self, call: ToolCall, ctx: ToolContext) -> ToolResult:
        tool = self._tools.get(call.name)
        if tool is None:
            return ToolResult(call_id=call.id, log=f"unknown tool: {call.name}", ok=False)
        try:
            log = tool.run(call.arguments, ctx)
            return ToolResult(call_id=call.id, log=log, ok=True)
        except Exception as exc:  # noqa: BLE001 - degrade, don't crash the loop
            return ToolResult(call_id=call.id, log=f"{type(exc).__name__}: {exc}", ok=False)
