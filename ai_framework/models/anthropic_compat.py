"""Anthropic-compatible chat backend — drives ``/messages`` endpoints over plain HTTP.

The sibling :mod:`ai_framework.models.openai_compat` speaks the OpenAI ``/chat/completions``
shape; this one speaks the Anthropic ``/messages`` shape (``x-api-key`` + ``anthropic-version``,
``tool_use``/``tool_result`` blocks). It exists so the RouterBackend can rotate over accounts
whose ``api_style`` is ``anthropic`` — Claude Code (OAuth), GLM Coding, Kimi Coding, Minimax,
and the native Anthropic API — without pulling in the ``anthropic`` SDK (which is env-key only).

Same ``HttpError``/``TransportError`` contract as the OpenAI adapter, so the router's cooldown
logic classifies 429/401/403 identically. OAuth accounts send the token as a Bearer header
instead of ``x-api-key`` (that is how Anthropic's OAuth sessions authenticate).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError as _UrllibHTTPError
from urllib.error import URLError
from urllib.request import Request, urlopen

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn
from ai_framework.models.base import ActResponse
from ai_framework.models.openai_compat import HttpError, TransportError

HttpPost = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]

ANTHROPIC_VERSION = "2023-06-01"


def _urllib_post(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    req = Request(
        url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST"
    )
    try:
        with urlopen(req, timeout=180) as resp:  # noqa: S310 - host comes from operator config
            return json.loads(resp.read())
    except _UrllibHTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        raise HttpError(exc.code, body) from exc
    except (URLError, OSError) as exc:
        raise TransportError(str(getattr(exc, "reason", exc))) from exc


class AnthropicCompatBackend:
    """Hermes turns over any Anthropic-compatible ``/messages`` endpoint."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        name: str = "anthropic-compat",
        max_tokens: int = 2048,
        http_post: HttpPost | None = None,
        extra_headers: dict[str, str] | None = None,
        oauth: bool = False,
    ) -> None:
        self.name = name
        self._url = base_url.rstrip("/") + "/messages"
        self._model = model
        self._key = api_key
        self._max_tokens = max_tokens
        self._post = http_post or _urllib_post
        self._extra = extra_headers or {}
        self._oauth = oauth

    def _headers(self) -> dict[str, str]:
        headers = {"anthropic-version": ANTHROPIC_VERSION, **self._extra}
        if self._key:
            # OAuth sessions authenticate with a Bearer token; API keys use x-api-key.
            if self._oauth:
                headers["Authorization"] = f"Bearer {self._key}"
            else:
                headers["x-api-key"] = self._key
        return headers

    def _tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
            for t in tools
        ]

    def _messages(self, transcript: list[Turn], config: RunConfig) -> list[dict[str, Any]]:
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
        if not messages:  # seed the goal when there is nothing but the system prompt
            messages.append({"role": "user", "content": f"Begin. Goal: {config.goal}"})
        return messages

    def act(
        self, system: str, transcript: list[Turn], config: RunConfig, tools: list[dict[str, Any]]
    ) -> ActResponse:
        payload = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "system": system,
            "messages": self._messages(transcript, config),
            "tools": self._tools(tools),
        }
        resp = self._post(self._url, payload, self._headers())
        reasoning: list[str] = []
        calls: list[ToolCall] = []
        for block in resp.get("content") or []:
            btype = block.get("type")
            if btype == "text":
                reasoning.append(block.get("text", ""))
            elif btype == "tool_use":
                calls.append(
                    ToolCall(
                        id=block.get("id", "call-0"),
                        name=block["name"],
                        arguments=dict(block.get("input") or {}),
                    )
                )
        return ActResponse(reasoning="\n".join(reasoning), tool_calls=calls, done=not calls)

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        messages = self._messages(transcript, config)
        messages.append(
            {"role": "user", "content": "From the logs above, state the single next step."}
        )
        payload = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "system": system,
            "messages": messages,
        }
        resp = self._post(self._url, payload, self._headers())
        return "".join(
            b.get("text", "") for b in (resp.get("content") or []) if b.get("type") == "text"
        )
