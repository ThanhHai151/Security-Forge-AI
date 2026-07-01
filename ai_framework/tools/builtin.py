"""Built-in starter tools: ``http_get`` and ``note_finding``.

``http_get`` enforces the safety gate from ``ARCHITECTURE.md``: it will only fetch
localhost or an explicitly authorized target. ``note_finding`` is pure and always safe.
"""

from __future__ import annotations

from typing import Any
from urllib.request import urlopen

from ai_framework.tools.base import ToolContext, require_authorized


class HttpGetTool:
    name = "http_get"
    description = "Fetch a URL with HTTP GET. Localhost or authorized targets only."
    touches_network = True  # OPSEC pacing applies
    mutating = False  # a plain GET is idempotent recon

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Absolute http(s) URL"}},
            "required": ["url"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        url = args["url"]
        require_authorized(url, ctx)
        with urlopen(url, timeout=10) as resp:  # noqa: S310 - host is gated above
            body = resp.read(4096).decode("utf-8", "replace")
            return f"HTTP {resp.status} {url}\n{body}"


class NoteFindingTool:
    name = "note_finding"
    description = (
        "Record a structured finding for the report: title, detail, severity "
        "(info|low|medium|high|critical), optional evidence, KB reference, and tags. "
        "Local and always safe."
    )
    touches_network = False  # local only — no OPSEC pacing
    mutating = False

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "detail": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Impact of the finding; defaults to info.",
                },
                "evidence": {
                    "type": "string",
                    "description": "The observed request/response or output that proves it.",
                },
                "kb_ref": {"type": "string", "description": "Related knowledge-base note id."},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["title"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        title = args["title"]
        detail = args.get("detail", "")
        severity = args.get("severity", "info")
        return f"FINDING [{severity}]: {title}\n{detail}".rstrip()
