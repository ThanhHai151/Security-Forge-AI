"""Built-in starter tools: ``http_get`` and ``note_finding``.

``http_get`` enforces the safety gate from ``ARCHITECTURE.md``: it will only fetch
localhost or an explicitly authorized target. ``note_finding`` is pure and always safe.
"""

from __future__ import annotations

from typing import Any

from ai_framework.tools.base import ToolContext, require_authorized
from ai_framework.tools.session import session_of


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
        with session_of(ctx).open(url, 10) as resp:  # session: persistent cookies/proxy/UA
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
                "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
                "cvss_vector": {"type": "string", "description": "Validated CVSS vector."},
                "cwe": {"type": "array", "items": {"type": "string"}},
                "owasp": {"type": "string"},
                "wstg": {"type": "array", "items": {"type": "string"}},
                "attack": {"type": "array", "items": {"type": "string"}},
                "affected_assets": {"type": "array", "items": {"type": "string"}},
                "remediation_owner": {"type": "string"},
                "repro": {
                    "type": "object",
                    "description": (
                        "Proof: a request to replay + what confirms it, so the finding is "
                        "auto-verified. {request:{method,url,headers,body}, expect:'marker in "
                        "response', expect_status:200}. Provide it whenever you can reproduce."
                    ),
                    "properties": {
                        "request": {"type": "object"},
                        "expect": {"type": "string"},
                        "expect_status": {"type": "integer"},
                    },
                },
            },
            "required": ["title"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        title = args["title"]
        detail = args.get("detail", "")
        severity = args.get("severity", "info")
        return f"FINDING [{severity}]: {title}\n{detail}".rstrip()


class RecordAssetTool:
    name = "record_asset"
    description = (
        "Record discovered attack surface into the recon graph so later steps reason over "
        "structure, not prose. kind ∈ {endpoint, param, form, tech, host, subdomain, cookie, "
        "other}. Record one (kind+value) or many via 'assets'. Local and always safe."
    )
    touches_network = False
    mutating = False

    @property
    def json_schema(self) -> dict[str, Any]:
        kind: dict[str, Any] = {
            "type": "string",
            "enum": ["endpoint", "param", "form", "tech", "host", "subdomain", "cookie", "other"],
        }
        item: dict[str, Any] = {
            "type": "object",
            "properties": {
                "kind": kind,
                "value": {"type": "string", "description": "URL / param name / tech / host"},
                "detail": {"type": "string"},
            },
        }
        return {
            "type": "object",
            "properties": {
                "kind": kind,
                "value": {"type": "string"},
                "detail": {"type": "string"},
                "assets": {"type": "array", "items": item, "description": "Record several at once"},
            },
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        rows = args.get("assets")
        if not isinstance(rows, list):
            rows = [args]
        recorded = [
            f"{r.get('kind', 'other')}:{r.get('value', '')}" for r in rows if r.get("value")
        ]
        if not recorded:
            return "no asset recorded (provide kind + value, or an 'assets' list)"
        return "recorded assets: " + ", ".join(recorded)
