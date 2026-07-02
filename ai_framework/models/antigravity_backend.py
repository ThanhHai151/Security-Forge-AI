"""Antigravity (Google Cloud Code Assist) chat backend.

Antigravity rides Google's ``cloudcode-pa`` Code Assist API with a Gemini-shaped request wrapped
in an Antigravity envelope. This subclasses :class:`GeminiBackend` and adds the pieces 9router's
``executors/antigravity.js`` needs to be accepted upstream:

* the ``{project, model, userAgent, requestType, requestId, request}`` envelope,
* stripping the thinking/reasoning fields Google rejects,
* capping ``maxOutputTokens`` at 16384,
* sanitizing tool names to Gemini's allowed pattern and forcing ``VALIDATED`` calling mode,
* Antigravity client headers (``User-Agent``, ``x-request-source``).

Antigravity is deprecated/RISK_NOTICE upstream and depends on a hard-coded OAuth client and
these exact headers; it can break without notice.

NOTE: 9router additionally cloaks client tools (``_ide`` suffix + ~21 decoy "unavailable" tools)
as an anti-ban measure. That layer is not yet ported — see ``cloak_tools`` below. Chat works
without it; add it if requests start getting rejected.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from ai_framework.agent.contracts import RunConfig, Turn
from ai_framework.models.gemini_backend import GeminiBackend

_MAX_OUTPUT_TOKENS = 16384
_TOOL_NAME_RE = re.compile(r"[^a-zA-Z0-9_.:\-]")
# Fields Google's Code Assist endpoint rejects on the wrapped Gemini request.
_THINKING_FIELDS = (
    "thinking",
    "reasoning_effort",
    "thinkingConfig",
    "output_config",
    "reasoning",
)


def _sanitize_tool_name(name: str) -> str:
    """Coerce a tool name into Gemini's ``[a-zA-Z_][a-zA-Z0-9_.:-]{0,63}`` shape."""
    cleaned = _TOOL_NAME_RE.sub("_", name)[:64]
    if cleaned and not re.match(r"[a-zA-Z_]", cleaned[0]):
        cleaned = f"_{cleaned}"[:64]
    return cleaned or "tool"


class AntigravityBackend(GeminiBackend):
    """Hermes turns over Google Cloud Code Assist (Antigravity)."""

    def __init__(self, base_url: str = "", **kwargs: Any) -> None:
        super().__init__(
            base_url=base_url or "https://daily-cloudcode-pa.googleapis.com/v1internal",
            cli_style=True,
            name=kwargs.pop("name", "antigravity"),
            **kwargs,
        )

    def _url(self) -> str:
        return f"{self._base}:generateContent"

    def _headers(self) -> dict[str, str]:
        headers = super()._headers()
        headers.setdefault("User-Agent", "antigravity/1.107.0 darwin/arm64")
        headers.setdefault("x-request-source", "local")
        return headers

    def _tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        decls = super()._tools(tools)
        for group in decls:
            for fn in group.get("functionDeclarations", []):
                fn["name"] = _sanitize_tool_name(fn["name"])
        return decls

    def _request(
        self, system: str, transcript: list[Turn], config: RunConfig, tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        request = super()._request(system, transcript, config, tools)
        # Google rejects thinking/reasoning knobs on this surface.
        for field in _THINKING_FIELDS:
            request.pop(field, None)
        gen = request.get("generationConfig") or {}
        gen["maxOutputTokens"] = min(
            gen.get("maxOutputTokens", _MAX_OUTPUT_TOKENS), _MAX_OUTPUT_TOKENS
        )
        request["generationConfig"] = gen
        if "toolConfig" in request:
            request["toolConfig"] = {"functionCallingConfig": {"mode": "VALIDATED"}}
        return request

    def _payload(
        self, system: str, transcript: list[Turn], config: RunConfig, tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        request = self._request(system, transcript, config, tools)
        envelope: dict[str, Any] = {
            "model": self._model,
            "userAgent": "antigravity",
            "requestType": "agent",
            "requestId": f"agent-{uuid.uuid4()}",
            "request": request,
        }
        project = self._pd.get("projectId")
        if project:
            envelope["project"] = project
        return envelope

    def cloak_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Anti-ban tool cloaking (NOT YET PORTED).

        9router renames client tools with an ``_ide`` suffix and injects ~21 decoy
        "currently unavailable" tools whose names match Antigravity-native ones, then rewrites
        functionCall/functionResponse names in history to match. Port from
        ``Tool/9router/open-sse/executors/antigravity.js`` (``static cloakTools``) if upstream
        starts rejecting un-cloaked requests.
        """
        return tools
