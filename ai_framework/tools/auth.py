"""Authentication tools — establish a session the rest of the run reuses.

Most interesting bugs live *behind* auth (IDOR/BOLA, broken access control, CSRF, privilege
escalation). These tools populate the run's :class:`HttpSession` cookie jar / headers so every
later ``http_get`` / ``http_request`` is authenticated:

* ``login`` — optionally GET a page to scrape a CSRF/anti-forgery token out of its form, then
  POST credentials; the resulting session cookies are captured automatically.
* ``set_auth`` — set a persistent header (typically ``Authorization: Bearer <token>``) or a
  cookie directly, for token/JWT-based apps that don't use a login form.

Both are scope-gated. ``login`` is deliberately *not* flagged mutating: authenticating is
setup, not a destructive change, so it stays usable inside an autonomous campaign.
"""

from __future__ import annotations

import re
import urllib.parse
from http.cookiejar import Cookie
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

from ai_framework.tools.base import ToolContext, require_authorized
from ai_framework.tools.session import session_of

_TIMEOUT = 10
_MAX_BODY = 8192

# Best-effort CSRF/anti-forgery hidden-field scrapers (name-before-value and value-before-name).
_CSRF_TOKENISH = r"[\w.-]*(?:csrf|token|authenticity|nonce|xsrf)[\w.-]*"
_CSRF_PATTERNS = (
    re.compile(rf'name=["\']?({_CSRF_TOKENISH})["\']?[^>]*?value=["\']?([^"\'>\s]+)', re.I),
    re.compile(rf'value=["\']?([^"\'>\s]+)["\']?[^>]*?name=["\']?({_CSRF_TOKENISH})["\']?', re.I),
    re.compile(
        rf'<meta[^>]+name=["\']?({_CSRF_TOKENISH})["\']?[^>]+content=["\']?([^"\'>\s]+)', re.I
    ),
)


def _extract_csrf(html: str) -> tuple[str, str]:
    """Return ``(field_name, token)`` scraped from a login page, or ``("", "")``."""
    for i, pat in enumerate(_CSRF_PATTERNS):
        m = pat.search(html)
        if m:
            # pattern 1 is (value, name); the others are (name, value)
            return (m.group(2), m.group(1)) if i == 1 else (m.group(1), m.group(2))
    return "", ""


class LoginTool:
    name = "login"
    description = (
        "Authenticate to establish a session reused by later requests. POSTs form fields "
        "(e.g. username/password) to a URL; if csrf_url is given, first GETs it and auto-injects "
        "the anti-CSRF token. Session cookies are captured automatically. Authorized targets only."
    )
    touches_network = True
    mutating = False  # authenticating is setup, not a destructive change — usable in campaigns

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Login POST endpoint (absolute URL)"},
                "data": {"type": "object", "description": "Form fields, e.g. {username, password}"},
                "method": {"type": "string", "description": "HTTP method, default POST"},
                "csrf_url": {"type": "string", "description": "Page to scrape a CSRF token from"},
                "csrf_field": {"type": "string", "description": "Override the CSRF field name"},
            },
            "required": ["url", "data"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        url = args["url"]
        require_authorized(url, ctx)
        data = {str(k): str(v) for k, v in (args.get("data") or {}).items()}
        sess = session_of(ctx)
        notes: list[str] = []

        csrf_url = args.get("csrf_url")
        if csrf_url:
            require_authorized(csrf_url, ctx)
            try:
                with sess.open(csrf_url, _TIMEOUT) as resp:
                    page = resp.read(_MAX_BODY).decode("utf-8", "replace")
            except HTTPError as exc:
                page = exc.read(_MAX_BODY).decode("utf-8", "replace") if exc.fp else ""
            name, token = _extract_csrf(page)
            field = str(args.get("csrf_field") or name)
            if field and token:
                data[field] = token
                notes.append(f"CSRF token injected into {field!r}")
            else:
                notes.append("no CSRF token found on csrf_url")

        method = str(args.get("method", "POST")).upper()
        body = urllib.parse.urlencode(data).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        req = Request(url, data=body, headers=headers, method=method)  # noqa: S310 - gated
        try:
            with sess.open(req, _TIMEOUT) as resp:
                status = resp.status
        except HTTPError as exc:
            status = exc.code
        cookies = sess.cookies()
        notes.append(f"cookies now: {', '.join(cookies) or 'none'}")
        verdict = "session cookie set" if cookies else "no session cookie — login may have failed"
        return f"login POST {url} -> HTTP {status}\n{verdict}\n" + "\n".join(notes)


class SetAuthTool:
    name = "set_auth"
    description = (
        "Set a persistent auth credential on the session for token-based apps: either a header "
        "(default Authorization: Bearer <token>) or a cookie. Applies to every later request. "
        "No network — always safe."
    )
    touches_network = False
    mutating = False

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "Bearer token (sets Authorization)"},
                "header": {"type": "string", "description": "Header name (else Authorization)"},
                "value": {"type": "string", "description": "Explicit header value"},
                "cookie": {"type": "object", "description": "{name, value, domain} cookie to set"},
            },
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        sess = session_of(ctx)
        done: list[str] = []
        token = args.get("token")
        header = args.get("header")
        value = args.get("value")
        if token:
            sess.set_header("Authorization", f"Bearer {token}")
            done.append("set Authorization: Bearer <token>")
        elif header and value is not None:
            sess.set_header(str(header), str(value))
            done.append(f"set header {header}")
        cookie = args.get("cookie")
        if isinstance(cookie, dict) and cookie.get("name"):
            sess.jar.set_cookie(_make_cookie(cookie))
            done.append(f"set cookie {cookie['name']}")
        return "; ".join(done) or "nothing set (provide token, header+value, or cookie)"


def _make_cookie(spec: dict[str, Any]) -> Cookie:
    domain = str(spec.get("domain", "") or "")
    return Cookie(
        version=0, name=str(spec["name"]), value=str(spec.get("value", "")),
        port=None, port_specified=False, domain=domain, domain_specified=bool(domain),
        domain_initial_dot=domain.startswith("."), path=str(spec.get("path", "/")),
        path_specified=True, secure=bool(spec.get("secure", False)), expires=None,
        discard=True, comment=None, comment_url=None, rest={}, rfc2109=False,
    )
