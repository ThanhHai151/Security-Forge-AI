"""Built-in starter tools: ``http_get`` and ``note_finding``.

``http_get`` enforces the safety gate from ``ARCHITECTURE.md``: it will only fetch
localhost or an explicitly authorized target. ``note_finding`` is pure and always safe.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen

from ai_framework.tools.base import ToolContext

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class HttpGetTool:
    name = "http_get"
    description = "Fetch a URL with HTTP GET. Localhost or authorized targets only."

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Absolute http(s) URL"}},
            "required": ["url"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        url = args["url"]
        host = urlparse(url).hostname or ""
        if host not in _LOCAL_HOSTS and host not in ctx.authorized_targets:
            raise PermissionError(
                f"target not authorized: {host!r} (authorize it in RunConfig.authorized_targets)"
            )
        with urlopen(url, timeout=10) as resp:  # noqa: S310 - host is gated above
            body = resp.read(4096).decode("utf-8", "replace")
            return f"HTTP {resp.status} {url}\n{body}"


class NoteFindingTool:
    name = "note_finding"
    description = "Record a structured finding (title + detail). Always safe."

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "detail": {"type": "string"},
            },
            "required": ["title"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        title = args["title"]
        detail = args.get("detail", "")
        return f"FINDING: {title}\n{detail}".rstrip()
