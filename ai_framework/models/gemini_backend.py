"""Google Gemini ``generateContent`` chat backend.

Speaks Gemini's native ``contents``/``functionCall`` shape (not OpenAI or Anthropic), covering
two transports:

* **plain ``gemini``** — ``generativelanguage.googleapis.com/v1beta/models/{model}:generateContent``
  authenticated with an API key (``x-goog-api-key`` header).
* **``gemini-cli``** — ``cloudcode-pa.googleapis.com/v1internal:generateContent`` authenticated
  with an OAuth bearer token, with the Gemini request wrapped as ``{model, project, request}``.

Non-streaming only: :meth:`act` is a single request/response, so we call ``:generateContent``
(not ``:streamGenerateContent``) and read ``candidates[0].content.parts``. This class is also the
base for :class:`~ai_framework.models.antigravity_backend.AntigravityBackend`.
"""

from __future__ import annotations

from typing import Any

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn
from ai_framework.models.base import ActResponse
from ai_framework.models.openai_compat import HttpPost, _urllib_post


class GeminiBackend:
    """Hermes turns over Gemini ``generateContent``."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        name: str = "gemini",
        max_tokens: int = 2048,
        http_post: HttpPost | None = None,
        extra_headers: dict[str, str] | None = None,
        cli_style: bool = False,
        provider_data: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self._base = base_url.rstrip("/")
        self._model = model
        self._key = api_key
        self._max_tokens = max_tokens
        self._post = http_post or _urllib_post
        self._extra = extra_headers or {}
        self._cli = cli_style
        self._pd = provider_data or {}

    # -- URL / headers (overridable by subclasses) ---------------------------

    def _url(self) -> str:
        if self._cli:
            return f"{self._base}:generateContent"
        return f"{self._base}/models/{self._model}:generateContent"

    def _headers(self) -> dict[str, str]:
        headers = {**self._extra}
        if self._key:
            if self._cli:
                headers["Authorization"] = f"Bearer {self._key}"
            else:
                headers["x-goog-api-key"] = self._key
        return headers

    # -- request construction ------------------------------------------------

    def _tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not tools:
            return []
        return [
            {
                "functionDeclarations": [
                    {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema") or {"type": "object", "properties": {}},
                    }
                    for t in tools
                ]
            }
        ]

    def _contents(
        self, transcript: list[Turn], config: RunConfig
    ) -> list[dict[str, Any]]:
        """Render the transcript as Gemini ``contents`` (roles ``user``/``model``)."""
        contents: list[dict[str, Any]] = []
        if not transcript:
            contents.append({"role": "user", "parts": [{"text": f"Begin. Goal: {config.goal}"}]})
        for turn in transcript:
            parts: list[dict[str, Any]] = []
            if turn.reasoning:
                parts.append({"text": turn.reasoning})
            name_by_id: dict[str, str] = {}
            for tc in turn.tool_calls:
                name_by_id[tc.id] = tc.name
                parts.append({"functionCall": {"name": tc.name, "args": tc.arguments}})
            if parts:
                contents.append({"role": "model", "parts": parts})
            if turn.tool_results:
                # Guard: Gemini requires a model turn immediately before functionResponse.
                # If no model content was emitted above (empty reasoning + no tool calls),
                # insert a placeholder so the conversation stays valid.
                if not parts:
                    contents.append({"role": "model", "parts": [{"text": "..."}]})
                contents.append(
                    {
                        "role": "user",
                        "parts": [
                            {
                                "functionResponse": {
                                    "name": name_by_id.get(tr.call_id, tr.call_id),
                                    "response": {"result": tr.log},
                                }
                            }
                            for tr in turn.tool_results
                        ],
                    }
                )
        return contents

    def _request(
        self, system: str, transcript: list[Turn], config: RunConfig, tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """The bare Gemini request body (before any transport wrapping)."""
        request: dict[str, Any] = {
            "contents": self._contents(transcript, config),
            "generationConfig": {"maxOutputTokens": self._max_tokens},
        }
        if system:
            request["systemInstruction"] = {"parts": [{"text": system}]}
        tool_decls = self._tools(tools)
        if tool_decls:
            request["tools"] = tool_decls
            request["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}
        return request

    def _payload(
        self, system: str, transcript: list[Turn], config: RunConfig, tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        request = self._request(system, transcript, config, tools)
        if self._cli:
            wrapped: dict[str, Any] = {"model": self._model, "request": request}
            project = self._pd.get("projectId")
            if project:
                wrapped["project"] = project
            return wrapped
        return request

    # -- response decode ------------------------------------------------------

    def _decode(self, resp: dict[str, Any]) -> ActResponse:
        # gemini-cli wraps the response under "response"; plain gemini does not.
        data = resp.get("response", resp)
        candidates = data.get("candidates") or []
        reasoning_parts: list[str] = []
        calls: list[ToolCall] = []
        if candidates:
            parts = (candidates[0].get("content") or {}).get("parts") or []
            for i, part in enumerate(parts):
                if "text" in part and part["text"]:
                    reasoning_parts.append(part["text"])
                elif "functionCall" in part:
                    fc = part["functionCall"]
                    calls.append(
                        ToolCall(
                            id=f"call-{i}",
                            name=fc.get("name", ""),
                            arguments=fc.get("args") or {},
                        )
                    )
        return ActResponse(
            reasoning="\n".join(reasoning_parts).strip(), tool_calls=calls, done=not calls
        )

    # -- Backend protocol -----------------------------------------------------

    def act(
        self,
        system: str,
        transcript: list[Turn],
        config: RunConfig,
        tools: list[dict[str, Any]],
    ) -> ActResponse:
        resp = self._post(self._url(), self._payload(system, transcript, config, tools),
                          self._headers())
        return self._decode(resp)

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        prompt = f"{system}\n\nFrom the logs above, state the single next step."
        resp = self._post(self._url(), self._payload(prompt, transcript, config, []),
                          self._headers())
        return self._decode(resp).reasoning
