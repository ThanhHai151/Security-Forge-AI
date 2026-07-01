"""Session/auth + OPSEC transport: cookie persistence, CSRF login, bearer, UA, proxy opener."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import ProxyHandler

import pytest

from ai_framework.tools.auth import LoginTool, SetAuthTool, _extract_csrf
from ai_framework.tools.base import ToolContext
from ai_framework.tools.builtin import HttpGetTool
from ai_framework.tools.session import HttpSession


class _Handler(BaseHTTPRequestHandler):
    """A tiny app: /login (GET form + POST sets cookie), /me echoes what it received."""

    def log_message(self, *a):  # noqa: D401 - silence test server
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/login":
            self._send(200, '<form><input name="csrf_token" value="Tok123"></form>')
        elif self.path == "/me":
            cookie = self.headers.get("Cookie", "")
            ua = self.headers.get("User-Agent", "")
            auth = self.headers.get("Authorization", "")
            self._send(200, f"cookie=[{cookie}] ua=[{ua}] auth=[{auth}]")
        else:
            self._send(404, "nope")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        self.server.last_post_body = body  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"logged-in")

    def _send(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    srv.last_post_body = ""  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", srv
    finally:
        srv.shutdown()
        t.join()


# ── CSRF extraction (pure) ──
def test_extract_csrf_from_hidden_input():
    name, tok = _extract_csrf('<input type="hidden" name="csrf_token" value="Tok123">')
    assert name == "csrf_token" and tok == "Tok123"


def test_extract_csrf_value_before_name():
    name, tok = _extract_csrf('<input value="ZZ9" name="authenticity_token">')
    assert name == "authenticity_token" and tok == "ZZ9"


# ── login establishes a session that later requests reuse ──
def test_login_captures_cookie_and_it_persists_to_next_request(server):
    base, srv = server
    sess = HttpSession()
    ctx = ToolContext(session=sess)  # 127.0.0.1 is always in-scope
    out = LoginTool().run(
        {"url": f"{base}/login", "data": {"username": "admin", "password": "x"},
         "csrf_url": f"{base}/login"},
        ctx,
    )
    assert "session cookie set" in out
    assert "CSRF token injected into 'csrf_token'" in out
    assert "csrf_token=Tok123" in srv.last_post_body  # the scraped token was POSTed
    # Now a plain GET carries the session cookie automatically.
    me = HttpGetTool().run({"url": f"{base}/me"}, ctx)
    assert "sessionid=abc123" in me


def test_custom_user_agent_is_sent(server):
    base, _ = server
    ctx = ToolContext(session=HttpSession(user_agent="pwn/1.0"))
    me = HttpGetTool().run({"url": f"{base}/me"}, ctx)
    assert "ua=[pwn/1.0]" in me


def test_set_auth_bearer_persists_across_requests(server):
    base, _ = server
    sess = HttpSession()
    ctx = ToolContext(session=sess)
    SetAuthTool().run({"token": "JWT.abc.def"}, ctx)
    me = HttpGetTool().run({"url": f"{base}/me"}, ctx)
    assert "auth=[Bearer JWT.abc.def]" in me


def test_set_auth_reports_nothing_when_empty():
    out = SetAuthTool().run({}, ToolContext(session=HttpSession()))
    assert "nothing set" in out


# ── OPSEC transport: proxy opener is actually configured ──
def test_proxy_handler_is_installed_when_proxy_set():
    sess = HttpSession(proxy="http://127.0.0.1:8080")
    assert sess.proxy == "http://127.0.0.1:8080"
    assert any(isinstance(h, ProxyHandler) for h in sess._opener.handlers)


def test_no_proxy_handler_when_unset():
    sess = HttpSession()
    # A bare session installs no explicit ProxyHandler (urllib defaults still apply).
    assert not any(
        isinstance(h, ProxyHandler) and h.proxies for h in sess._opener.handlers
    )
