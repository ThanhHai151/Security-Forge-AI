"""OpenRouter backend — Hermes turns over OpenRouter's OpenAI-compatible chat API.

Selected when ``RunConfig.backend == "openrouter"``. OpenRouter speaks the OpenAI
chat/completions tool-calling shape, so this adapter maps a Hermes ``Turn`` onto
``messages`` + ``tools`` and reads ``choices[0].message.tool_calls`` back. As with the
Claude adapter, the loop code does not change — only this file.

The API key comes from ``OPENROUTER_API_KEY`` (never from a committed file). Get one with
``python -m ai_framework.openrouter_login`` (OAuth PKCE) or paste an existing key into ``.env``.
No third-party dependency: it uses the stdlib ``urllib`` so offline runs need nothing extra.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any
from urllib.request import Request, urlopen

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn
from ai_framework.models.base import ActResponse

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"

# (url, json_payload, headers) -> parsed json response. Injectable so tests need no network.
HttpPost = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]


def _urllib_post(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    req = Request(
        url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST"
    )
    with urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https endpoint
        return json.loads(resp.read())


class OpenRouterBackend:
    name = "openrouter"

    def __init__(
        self,
        model: str | None = None,
        max_tokens: int = 2048,
        api_key: str | None = None,
        http_post: HttpPost | None = None,
    ) -> None:
        key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not set — run `python -m ai_framework.openrouter_login` "
                "to fetch one via OAuth, or paste a key into .env"
            )
        self._key = key
        self._model = model or os.environ.get("OPENROUTER_MODEL", DEFAULT_MODEL)
        self._max_tokens = max_tokens
        self._post = http_post or _urllib_post

    def _headers(self) -> dict[str, str]:
        # HTTP-Referer / X-Title are OpenRouter's optional attribution headers.
        return {
            "Authorization": f"Bearer {self._key}",
            "HTTP-Referer": "https://github.com/secforge",
            "X-Title": "SecForge",
        }

    def _tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

    def _messages(
        self, system: str, transcript: list[Turn], config: RunConfig
    ) -> list[dict[str, Any]]:
        """Render the transcript as OpenAI system/assistant/tool message blocks."""
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for turn in transcript:
            assistant: dict[str, Any] = {"role": "assistant", "content": turn.reasoning}
            if turn.tool_calls:
                assistant["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in turn.tool_calls
                ]
            messages.append(assistant)
            for tr in turn.tool_results:
                messages.append({"role": "tool", "tool_call_id": tr.call_id, "content": tr.log})
        if len(messages) == 1:  # nothing but the system prompt -> seed the goal
            messages.append({"role": "user", "content": f"Begin. Goal: {config.goal}"})
        return messages

    def act(
        self,
        system: str,
        transcript: list[Turn],
        config: RunConfig,
        tools: list[dict[str, Any]],
    ) -> ActResponse:
        payload = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": self._messages(system, transcript, config),
            "tools": self._tools(tools),
        }
        resp = self._post(API_URL, payload, self._headers())
        message = resp["choices"][0]["message"]
        calls: list[ToolCall] = []
        for i, tc in enumerate(message.get("tool_calls") or []):
            fn = tc["function"]
            raw = fn.get("arguments") or "{}"
            try:
                arguments = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                arguments = {}
            calls.append(
                ToolCall(id=tc.get("id") or f"call-{i}", name=fn["name"], arguments=arguments)
            )
        return ActResponse(
            reasoning=message.get("content") or "",
            tool_calls=calls,
            done=not calls,
        )

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        messages = self._messages(system, transcript, config)
        messages.append(
            {"role": "user", "content": "From the logs above, state the single next step."}
        )
        payload = {"model": self._model, "max_tokens": self._max_tokens, "messages": messages}
        resp = self._post(API_URL, payload, self._headers())
        return resp["choices"][0]["message"].get("content") or ""
