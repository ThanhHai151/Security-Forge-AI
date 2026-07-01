"""Recon / HTTP / decode tools — the catalog that makes SecForge an actual pentest agent.

Every network tool goes through ``require_authorized`` (localhost or an authorized target
only) and declares ``touches_network`` (for OPSEC pacing) and ``mutating`` (for the tighter
guardrail leash on state-changing actions). The decode/encode tool is local and always safe.

The set is deliberately small and defensive: fingerprint what is exposed, inspect security
posture, and transform payloads — not launch destructive attacks. Add more tools by dropping
a class here and registering it (extensibility = add a file, per ARCHITECTURE.md).
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.parse
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

from ai_framework.tools.base import ToolContext, require_authorized
from ai_framework.tools.session import session_of

_TIMEOUT = 10
_MAX_BODY = 4096

# Response headers a defender should be setting; their absence is worth noting.
_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _headers_text(headers: Any) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


class HttpRequestTool:
    name = "http_request"
    description = (
        "Send a crafted HTTP request (method, headers, body) and return status + headers + a "
        "body snippet. Localhost or authorized targets only. Use for probing beyond a plain GET."
    )
    touches_network = True
    mutating = True  # can POST/PUT/DELETE — held to the tighter guardrail leash

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Absolute http(s) URL"},
                "method": {"type": "string", "description": "GET/POST/PUT/DELETE/... default GET"},
                "headers": {"type": "object", "description": "Request headers as a map"},
                "body": {"type": "string", "description": "Request body (sent as UTF-8)"},
            },
            "required": ["url"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        url = args["url"]
        require_authorized(url, ctx)
        method = str(args.get("method", "GET")).upper()
        headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
        body = args.get("body")
        data = body.encode("utf-8") if isinstance(body, str) and body else None
        req = Request(url, data=data, headers=headers, method=method)  # noqa: S310 - gated
        try:
            with session_of(ctx).open(req, _TIMEOUT) as resp:  # session: cookies/proxy/UA
                snippet = resp.read(_MAX_BODY).decode("utf-8", "replace")
                return (
                    f"HTTP {resp.status} {method} {url}\n{_headers_text(resp.headers)}\n\n{snippet}"
                )
        except HTTPError as exc:  # a 4xx/5xx is a real, useful observation — not a tool failure
            snippet = exc.read(_MAX_BODY).decode("utf-8", "replace") if exc.fp else ""
            return f"HTTP {exc.code} {method} {url}\n{_headers_text(exc.headers)}\n\n{snippet}"


class InspectHeadersTool:
    name = "inspect_headers"
    description = (
        "Fetch a URL and analyse its response headers for missing security headers "
        "(HSTS, CSP, X-Frame-Options, ...) and disclosed server/tech. Read-only."
    )
    touches_network = True
    mutating = False

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
        req = Request(url, method="GET")  # noqa: S310 - gated
        with session_of(ctx).open(req, _TIMEOUT) as resp:  # session: cookies/proxy/UA
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
        present = [h for h in _SECURITY_HEADERS if h in headers]
        missing = [h for h in _SECURITY_HEADERS if h not in headers]
        disclosed = {k: headers[k] for k in ("server", "x-powered-by", "via") if k in headers}
        lines = [f"HTTP {status} {url}", ""]
        lines.append(f"Security headers present : {', '.join(present) or 'none'}")
        lines.append(f"Security headers MISSING : {', '.join(missing) or 'none'}")
        if disclosed:
            shown = ", ".join(f"{k}={v}" for k, v in disclosed.items())
            lines.append(f"Tech disclosure         : {shown}")
        return "\n".join(lines)


class RobotsSitemapTool:
    name = "fetch_robots_sitemap"
    description = (
        "Fetch /robots.txt and /sitemap.xml for a site to map disallowed paths and exposed "
        "endpoints. Read-only. Localhost or authorized targets only."
    )
    touches_network = True
    mutating = False

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base site URL (scheme + host)"}
            },
            "required": ["url"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        base = args["url"]
        require_authorized(base, ctx)
        parts = urllib.parse.urlsplit(base)
        root = f"{parts.scheme}://{parts.netloc}"
        sess = session_of(ctx)
        out: list[str] = []
        for name in ("robots.txt", "sitemap.xml"):
            target = f"{root}/{name}"
            try:
                with sess.open(target, _TIMEOUT) as resp:  # session: cookies/proxy/UA
                    text = resp.read(_MAX_BODY).decode("utf-8", "replace")
                    out.append(f"=== {target} (HTTP {resp.status}) ===\n{text}")
            except (HTTPError, URLError) as exc:
                out.append(f"=== {target} — unavailable: {exc} ===")
        return "\n\n".join(out)


class DecodeEncodeTool:
    name = "decode_encode"
    description = (
        "Transform a value locally: base64/url/hex encode or decode, or jwt-decode (header + "
        "payload, no signature check). No network — always safe."
    )
    touches_network = False
    mutating = False

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "op": {
                    "type": "string",
                    "enum": [
                        "base64-encode", "base64-decode",
                        "url-encode", "url-decode",
                        "hex-encode", "hex-decode",
                        "jwt-decode",
                    ],
                },
                "value": {"type": "string"},
            },
            "required": ["op", "value"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        op = args["op"]
        value = args["value"]
        if op == "base64-encode":
            return base64.b64encode(value.encode()).decode()
        if op == "base64-decode":
            return base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "replace")
        if op == "url-encode":
            return urllib.parse.quote(value)
        if op == "url-decode":
            return urllib.parse.unquote(value)
        if op == "hex-encode":
            return value.encode().hex()
        if op == "hex-decode":
            return binascii.unhexlify(value).decode("utf-8", "replace")
        if op == "jwt-decode":
            return self._jwt_decode(value)
        raise ValueError(f"unknown op: {op}")

    @staticmethod
    def _b64url(segment: str) -> str:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)).decode(
            "utf-8", "replace"
        )

    def _jwt_decode(self, token: str) -> str:
        parts = token.split(".")
        if len(parts) < 2:
            raise ValueError("not a JWT (expected header.payload.signature)")
        header = self._b64url(parts[0])
        payload = self._b64url(parts[1])
        try:  # pretty-print if valid JSON
            header = json.dumps(json.loads(header), indent=2)
            payload = json.dumps(json.loads(payload), indent=2)
        except json.JSONDecodeError:
            pass
        return f"header:\n{header}\n\npayload:\n{payload}\n\n(signature not verified)"
