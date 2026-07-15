"""HttpSession — one stateful HTTP client shared across a run's network tools.

Real web testing is stateful: you log in, get a cookie, and every later request must carry it;
you may route through Burp/Tor; you may want a non-default User-Agent. A bare ``urlopen`` per
tool call throws all of that away. ``HttpSession`` wraps a urllib ``OpenerDirector`` with:

* a **cookie jar** (``http.cookiejar``) so a session established by the ``login`` tool persists
  across every subsequent ``http_get`` / ``http_request`` in the same run;
* an optional **proxy** (HTTP/HTTPS/SOCKS-via-HTTP-proxy) so traffic can go through Burp or a
  pivot — turning the OPSEC advice in the system prompt into something actually enforced;
* a configurable **User-Agent** and default headers (blend in, or identify honestly).

The loop builds one session from ``RunConfig`` and puts it on the ``ToolContext``; tools reach
it via :func:`session_of`. Stdlib-only; no dependency.
"""

from __future__ import annotations

import http.cookiejar
from collections.abc import Callable
from typing import Any
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

from ai_framework.harness.netguard import EgressPolicy, guarded_handlers

DEFAULT_UA = "SecForge/1.0 (+authorized-engagement)"


class ScopedRedirectHandler(HTTPRedirectHandler):
    """Re-check scope before urllib follows a redirect to a new URL."""

    def __init__(self, validator: Callable[[str], None]) -> None:
        super().__init__()
        self._validator = validator

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        self._validator(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpSession:
    """A cookie-persisting, optionally-proxied HTTP opener for one run."""

    def __init__(
        self,
        user_agent: str | None = None,
        proxy: str | None = None,
        default_headers: dict[str, str] | None = None,
        redirect_validator: Callable[[str], None] | None = None,
        egress_policy: EgressPolicy | None = None,
    ) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.user_agent = user_agent or DEFAULT_UA
        self.proxy = (proxy or "").strip()
        self.default_headers = dict(default_headers or {})
        self.redirect_validator = redirect_validator
        # Resolve-pin-and-gate every direct connection so an in-scope name that resolves (or
        # rebinds) to a private/metadata address is refused at the socket. Skipped when a proxy
        # is configured — the operator's proxy then owns egress and the lexical gate still runs.
        self.egress_policy = egress_policy or EgressPolicy()
        self._opener = self._build_opener()

    def _build_opener(self) -> OpenerDirector:
        handlers: list[Any] = [HTTPCookieProcessor(self.jar)]
        if self.redirect_validator is not None:
            handlers.append(ScopedRedirectHandler(self.redirect_validator))
        if self.proxy:
            handlers.append(ProxyHandler({"http": self.proxy, "https": self.proxy}))
        else:
            # Ignore ambient HTTP(S)_PROXY: an empty ProxyHandler stops urllib silently routing
            # authorized-engagement traffic through a proxy the operator never configured, and the
            # guarded handlers resolve-pin-and-gate every direct connection.
            handlers.append(ProxyHandler({}))
            handlers.extend(guarded_handlers(self.egress_policy))
        opener = build_opener(*handlers)
        # addheaders only fills headers the request didn't set, so per-call headers still win.
        opener.addheaders = [("User-Agent", self.user_agent), *self.default_headers.items()]
        return opener

    def set_header(self, name: str, value: str) -> None:
        """Set a persistent default header (e.g. ``Authorization: Bearer …``) and rebuild."""
        self.default_headers[name] = value
        self._opener = self._build_opener()

    def open(self, req: Request | str, timeout: float = 10.0) -> Any:
        """Open a request/URL through the session opener (cookies + proxy + UA applied)."""
        return self._opener.open(req, timeout=timeout)  # noqa: S310 - host gated by caller

    def cookies(self) -> dict[str, str]:
        """Current cookie name→value map (for session_info / assertions)."""
        return {c.name: c.value or "" for c in self.jar}


def session_of(ctx: Any) -> Any:
    """Return the run's session (anything with ``.open``), or a fresh ephemeral one.

    Duck-typed on purpose so tests can inject a stub opener without constructing a real session.
    """
    return getattr(ctx, "session", None) or HttpSession()
