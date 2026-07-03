"""Kiro (AWS CodeWhisperer) chat backend.

Kiro's chat surface is AWS CodeWhisperer's ``GenerateAssistantResponse`` — a JSON request that
returns a binary ``application/vnd.amazon.eventstream`` response, not JSON. This adapter:

* builds the ``conversationState`` request body (ported from 9router's
  ``translator/request/openai-to-kiro.js``),
* signs it per auth method (``api_key`` gets ``tokentype: API_KEY``; enterprise SSO gets
  ``TokenType: EXTERNAL_IDP``; OAuth/social send a plain bearer token),
* walks the host fallback list (``runtime.kiro.dev`` → ``codewhisperer`` → ``q``; amazonaws
  hosts first for api-key/enterprise credentials), and
* decodes the EventStream response (see ``eventstream.py``) into an :class:`ActResponse`.

Because the response is binary, this backend uses its own raw-bytes transport rather than the
JSON ``http_post`` the OpenAI/Anthropic adapters share. The transport is still injectable so
tests need no network.

Kiro is a reverse-engineered IDE surface (marked deprecated/RISK_NOTICE upstream); endpoints
and behaviour can change without notice.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError as _UrllibHTTPError
from urllib.error import URLError
from urllib.request import Request, urlopen

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn
from ai_framework.models.base import ActResponse
from ai_framework.models.eventstream import iter_events
from ai_framework.models.openai_compat import HttpError, TransportError

# Canonical CodeWhisperer streaming endpoints, in default fallback order.
_RUNTIME = "https://runtime.us-east-1.kiro.dev/generateAssistantResponse"
_CODEWHISPERER = "https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse"
_Q = "https://q.us-east-1.amazonaws.com/generateAssistantResponse"
_DEFAULT_ENDPOINTS = (_RUNTIME, _CODEWHISPERER, _Q)
# api-key / enterprise tokens are minted for the CodeWhisperer control plane, so those hosts
# must be tried first (mirrors 9router's getOrderedBaseUrls).
_AMAZON_FIRST = (_CODEWHISPERER, _Q, _RUNTIME)

# (url, json_payload, headers) -> (status, raw_body_bytes). Injectable for tests.
RawHttpPost = Callable[[str, dict[str, Any], dict[str, str]], tuple[int, bytes]]


def _urllib_post_raw(
    url: str, payload: dict[str, Any], headers: dict[str, str]
) -> tuple[int, bytes]:
    data = json.dumps(payload).encode()
    req = Request(
        url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST"
    )
    try:
        with urlopen(req, timeout=180) as resp:  # noqa: S310 - host from operator/provider config
            return resp.status, resp.read()
    except _UrllibHTTPError as exc:
        body = b""
        try:
            body = exc.read()
        except Exception:  # noqa: BLE001 - body is best-effort
            pass
        raise HttpError(exc.code, body.decode("utf-8", "replace")) from exc
    except (URLError, OSError) as exc:
        raise TransportError(str(getattr(exc, "reason", exc))) from exc


def _resolve_model(model: str) -> tuple[str, bool]:
    """Map a SecForge model id to (upstream_model, thinking_enabled).

    ``-agentic`` is a synthetic 9router suffix (same upstream model) and is dropped;
    ``-thinking`` toggles Kiro's ``<thinking_mode>`` injection and is also dropped.
    """
    upstream = model
    thinking = False
    if upstream.endswith("-agentic"):
        upstream = upstream[: -len("-agentic")]
    if upstream.endswith("-thinking"):
        upstream = upstream[: -len("-thinking")]
        thinking = True
    return upstream, thinking


class KiroBackend:
    """Hermes turns over AWS CodeWhisperer's ``GenerateAssistantResponse``."""

    def __init__(
        self,
        base_url: str = "",
        model: str = "claude-sonnet-4.5",
        api_key: str | None = None,
        name: str = "kiro",
        max_tokens: int = 32000,
        http_post: RawHttpPost | None = None,
        extra_headers: dict[str, str] | None = None,
        provider_data: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self._model = model
        self._key = api_key
        self._max_tokens = max_tokens
        self._post = http_post or _urllib_post_raw
        self._extra = extra_headers or {}
        self._pd = provider_data or {}
        # Normalise base_url: strip any trailing slash/path and append the
        # canonical endpoint path so custom/enterprise base URLs work.
        self._base_url = base_url.rstrip("/") if base_url else ""

    # -- request construction -------------------------------------------------

    def _endpoints(self) -> tuple[str, ...]:
        """Return the ordered list of CodeWhisperer endpoints to try.

        When a custom ``base_url`` is provided (e.g. an enterprise Kiro host or
        a specific regional fallback), prepend it to the default list so it is
        tried first without losing the built-in fallbacks.
        """
        auth = self._pd.get("authMethod", "")
        defaults = _AMAZON_FIRST if auth in ("api_key", "external_idp") else _DEFAULT_ENDPOINTS
        if not self._base_url:
            return defaults
        # Normalise: if caller passed just the host, append the API path.
        custom = self._base_url
        if not custom.endswith("/generateAssistantResponse"):
            custom = f"{custom}/generateAssistantResponse"
        if custom in defaults:
            return defaults  # already in the list — keep original order
        return (custom, *defaults)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.amazon.eventstream",
            "X-Amz-Target": "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
            "User-Agent": "AWS-SDK-JS/3.0.0 kiro-ide/1.0.0",
            "X-Amz-User-Agent": "aws-sdk-js/3.0.0 kiro-ide/1.0.0",
            "Amz-Sdk-Request": "attempt=1; max=3",
            "Amz-Sdk-Invocation-Id": str(uuid.uuid4()),
            **self._extra,
        }
        auth = self._pd.get("authMethod", "")
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
            if auth == "api_key":
                headers["tokentype"] = "API_KEY"
            elif auth == "external_idp":
                headers["TokenType"] = "EXTERNAL_IDP"
        return headers

    def _tool_specs(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        specs = []
        for t in tools:
            schema = t.get("input_schema") or {"type": "object", "properties": {}, "required": []}
            schema = {**schema, "required": schema.get("required", [])}
            specs.append(
                {
                    "toolSpecification": {
                        "name": t["name"],
                        "description": t.get("description") or f"Tool: {t['name']}",
                        "inputSchema": {"json": schema},
                    }
                }
            )
        return specs

    def _history(self, transcript: list[Turn]) -> list[dict[str, Any]]:
        """Render prior turns as alternating user/assistant CodeWhisperer messages.

        Each turn becomes an ``assistantResponseMessage`` (reasoning + toolUses); the tool
        results that answered it become the following ``userInputMessage`` (toolResults).
        """
        history: list[dict[str, Any]] = []
        for turn in transcript:
            assistant: dict[str, Any] = {"content": turn.reasoning or "..."}
            if turn.tool_calls:
                assistant["toolUses"] = [
                    {"toolUseId": tc.id, "name": tc.name, "input": tc.arguments}
                    for tc in turn.tool_calls
                ]
            history.append({"assistantResponseMessage": assistant})
            if turn.tool_results:
                history.append(
                    {
                        "userInputMessage": {
                            "content": "Tool results below.",
                            "modelId": _resolve_model(self._model)[0],
                            "userInputMessageContext": {
                                "toolResults": [
                                    {
                                        "toolUseId": tr.call_id,
                                        "status": "success" if tr.ok else "error",
                                        "content": [{"text": tr.log}],
                                    }
                                    for tr in turn.tool_results
                                ]
                            },
                        }
                    }
                )
        return history

    def _payload(
        self, system: str, transcript: list[Turn], config: RunConfig, tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        upstream, thinking = _resolve_model(self._model)
        history = self._history(transcript)

        # Kiro has no system role: fold the system prompt into the current user message, with
        # the thinking-mode tag first (Kiro's only reasoning switch) if requested.
        prefix = []
        if thinking:
            prefix.append("<thinking_mode>enabled</thinking_mode>")
        if system:
            prefix.append(system)
        if not transcript:
            prefix.append(f"Begin. Goal: {config.goal}")
        content = "\n\n".join(prefix) or "continue"

        context: dict[str, Any] = {}
        if tools:
            context["tools"] = self._tool_specs(tools)

        current: dict[str, Any] = {
            "content": content,
            "modelId": upstream,
            "origin": "AI_EDITOR",
        }
        if context:
            current["userInputMessageContext"] = context

        payload: dict[str, Any] = {
            "conversationState": {
                "chatTriggerType": "MANUAL",
                # Derive a stable conversation ID from the run's goal+target so all
                # steps of the same run share one server-side conversation context.
                # (9router maintains conversationId per session; a fresh UUID every
                # call breaks server-side history tracking and double-counts quota.)
                "conversationId": hashlib.sha256(
                    f"{config.goal}:{config.target}".encode()
                ).hexdigest()[:32],
                "currentMessage": {"userInputMessage": current},
                "history": history,
            }
        }
        profile_arn = self._pd.get("profileArn")
        if profile_arn:
            payload["profileArn"] = profile_arn
        payload["inferenceConfig"] = {"maxTokens": self._max_tokens}
        return payload

    # -- transport + decode ---------------------------------------------------

    def _send(self, payload: dict[str, Any]) -> bytes:
        """POST to each endpoint in turn, advancing on 429/5xx/transport errors."""
        last: Exception | None = None
        for url in self._endpoints():
            try:
                status, body = self._post(url, payload, self._headers())
            except HttpError as exc:
                last = exc
                if exc.status == 429 or exc.status >= 500:
                    continue  # try the next surface
                raise
            except TransportError as exc:
                last = exc
                continue
            if status == 429 or status >= 500:
                last = HttpError(status, body.decode("utf-8", "replace"))
                continue
            return body
        if last:
            raise last
        raise TransportError("no Kiro endpoint reachable")

    def _decode(self, body: bytes) -> ActResponse:
        reasoning_parts: list[str] = []
        content_parts: list[str] = []
        # toolUseId -> {name, input_str, input_obj}
        tools: dict[str, dict[str, Any]] = {}
        order: list[str] = []

        for frame in iter_events(body):
            p = frame.payload if isinstance(frame.payload, dict) else {}
            etype = frame.event_type
            if etype == "assistantResponseEvent" and p.get("content"):
                content_parts.append(str(p["content"]))
            elif etype == "reasoningContentEvent":
                r = p.get("reasoningContentEvent", p)
                text = r if isinstance(r, str) else (r.get("text") or r.get("content") or "")
                if text:
                    reasoning_parts.append(str(text))
            elif etype == "toolUseEvent" and p:
                tid = p.get("toolUseId") or f"call-{len(order)}"
                slot = tools.get(tid)
                if slot is None:
                    slot = {"name": p.get("name") or "", "input_str": "", "input_obj": None}
                    tools[tid] = slot
                    order.append(tid)
                if p.get("name"):
                    slot["name"] = p["name"]
                inp = p.get("input")
                if isinstance(inp, str):
                    slot["input_str"] += inp
                elif isinstance(inp, dict):
                    slot["input_obj"] = inp

        calls: list[ToolCall] = []
        for tid in order:
            slot = tools[tid]
            args = slot["input_obj"]
            if args is None and slot["input_str"]:
                try:
                    args = json.loads(slot["input_str"])
                except json.JSONDecodeError:
                    args = {}
            calls.append(ToolCall(id=tid, name=slot["name"], arguments=args or {}))

        # Streamed chunks concatenate directly; reasoning (thinking) and answer text are
        # separated by a blank line when both are present.
        segments = [s for s in ("".join(reasoning_parts), "".join(content_parts)) if s]
        reasoning = "\n\n".join(segments).strip()
        return ActResponse(reasoning=reasoning, tool_calls=calls, done=not calls)

    # -- Backend protocol -----------------------------------------------------

    def act(
        self,
        system: str,
        transcript: list[Turn],
        config: RunConfig,
        tools: list[dict[str, Any]],
    ) -> ActResponse:
        return self._decode(self._send(self._payload(system, transcript, config, tools)))

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        prompt = f"{system}\n\nFrom the logs above, state the single next step."
        resp = self._decode(self._send(self._payload(prompt, transcript, config, [])))
        return resp.reasoning
