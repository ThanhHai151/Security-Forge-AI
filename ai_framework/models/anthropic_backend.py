"""Claude backend — maps the Hermes turn onto Anthropic native tool-use.

Selected when ``RunConfig.backend == "anthropic"``. The loop code does not change; only this
adapter does. The API key comes from ``ANTHROPIC_API_KEY`` (never from a file). Requires the
optional ``anthropic`` dependency: ``pip install -e ".[anthropic]"``.
"""

from __future__ import annotations

import os
from typing import Any

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn
from ai_framework.models.base import ActResponse

DEFAULT_MODEL = "claude-opus-4-8"


class AnthropicBackend:
    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, max_tokens: int = 2048) -> None:
        import anthropic  # imported lazily so offline runs need no dependency

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens

    def _messages(self, transcript: list[Turn]) -> list[dict[str, Any]]:
        """Render the transcript as Claude tool_use / tool_result message blocks."""
        messages: list[dict[str, Any]] = []
        for turn in transcript:
            content: list[dict[str, Any]] = []
            if turn.reasoning:
                content.append({"type": "text", "text": turn.reasoning})
            for tc in turn.tool_calls:
                content.append(
                    {"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments}
                )
            if content:
                messages.append({"role": "assistant", "content": content})
            if turn.tool_results:
                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_result", "tool_use_id": tr.call_id, "content": tr.log}
                            for tr in turn.tool_results
                        ],
                    }
                )
        return messages

    def _tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
            for t in tools
        ]

    def act(
        self,
        system: str,
        transcript: list[Turn],
        config: RunConfig,
        tools: list[dict[str, Any]],
    ) -> ActResponse:
        messages = self._messages(transcript)
        if not messages:
            messages = [{"role": "user", "content": f"Begin. Goal: {config.goal}"}]
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            tools=self._tools(tools),
            messages=messages,
        )
        reasoning_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in resp.content:
            if block.type == "text":
                reasoning_parts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input)))
        return ActResponse(
            reasoning="\n".join(reasoning_parts),
            tool_calls=calls,
            done=not calls,
        )

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        messages = self._messages(transcript)
        messages.append(
            {"role": "user", "content": "From the logs above, state the single next step."}
        )
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=messages,
        )
        return "".join(b.text for b in resp.content if b.type == "text")
