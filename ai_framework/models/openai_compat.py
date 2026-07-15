"""Generic OpenAI-compatible chat backend — drives local AI proxies.

9router (``http://localhost:20128/v1``) and Antigravity-Manager (``http://localhost:8045/v1``)
both expose the OpenAI ``/chat/completions`` tool-calling shape, as does any OpenAI-style
gateway. This adapter speaks that shape against an arbitrary ``base_url``, so the Hermes loop
can run on whichever provider/account the user picked inside those tools — SecForge never sees
the underlying credentials, only the proxy endpoint. Stdlib-only (urllib); no extra dependency.

The sibling ``openrouter_backend.py`` is the same protocol against a fixed hosted URL; this one
is parameterised so a proxy's ``base_url`` + ``model`` come from the RunConfig.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError as _UrllibHTTPError
from urllib.error import URLError
from urllib.request import Request, urlopen

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn
from ai_framework.agent.system import fence_untrusted
from ai_framework.models.base import ActResponse, normalize_usage


class HttpError(Exception):
    """A non-2xx HTTP response. ``status`` lets the router classify 429/401/403 for cooldown."""

    def __init__(self, status: int, body: str = "") -> None:
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}{(': ' + body[:200]) if body else ''}")


class TransportError(Exception):
    """A connection-level failure (host down, refused, DNS, timeout)."""


# (url, json_payload, headers) -> parsed json. Injectable so tests need no network.
HttpPost = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]


def _urllib_post(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    req = Request(
        url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST"
    )
    try:
        with urlopen(req, timeout=180) as resp:  # noqa: S310 - host comes from operator config
            return json.loads(resp.read())
    except _UrllibHTTPError as exc:  # 4xx/5xx — surface the status so callers can react
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - body is best-effort
            pass
        raise HttpError(exc.code, body) from exc
    except (URLError, OSError) as exc:
        raise TransportError(str(getattr(exc, "reason", exc))) from exc


class OpenAICompatBackend:
    """Hermes turns over any OpenAI-compatible ``/chat/completions`` endpoint."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        name: str = "openai-compat",
        max_tokens: int = 2048,
        http_post: HttpPost | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._key = api_key
        self._max_tokens = max_tokens
        self._post = http_post or _urllib_post
        self._extra = extra_headers or {}
        # Token usage from the most recent call, for the router's quota tracker (None until set).
        self.last_usage: dict[str, int] | None = None

    def _headers(self) -> dict[str, str]:
        headers = {"X-Title": "SecForge", **self._extra}
        if self._key:  # local proxies often accept any/no key; only send one if configured
            headers["Authorization"] = f"Bearer {self._key}"
        return headers

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
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tr.call_id,
                        "content": fence_untrusted(tr.log, empty_placeholder="(no output)"),
                    }
                )
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
        resp = self._post(self._url, payload, self._headers())
        self.last_usage = normalize_usage(resp.get("usage"))
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
        resp = self._post(self._url, payload, self._headers())
        self.last_usage = normalize_usage(resp.get("usage"))
        return resp["choices"][0]["message"].get("content") or ""
