"""OpenRouter OAuth PKCE login — fetch a user-controlled API key with no manual copy-paste.

    python -m ai_framework.openrouter_login

Opens OpenRouter's authorize page in your browser; after you approve, a one-shot localhost
server captures the ``?code=`` redirect, exchanges it for a key over PKCE, and writes
``OPENROUTER_API_KEY`` into ``.env``.

This does NOT script account creation: you log in and approve once in the browser (OpenRouter
requires a human there). All this automates is the code->key exchange and the .env write.

Flow — https://openrouter.ai/docs/use-cases/oauth-pkce :
  GET  https://openrouter.ai/auth?callback_url=<localhost>&code_challenge=<S256>&code_challenge_method=S256
  POST https://openrouter.ai/api/v1/auth/keys  {code, code_verifier, code_challenge_method:"S256"}
       -> {"key": "...", "user_id": "..."}
Localhost callbacks are allowed on any port, so a CLI can bind a free OS port for the redirect.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

AUTH_URL = "https://openrouter.ai/auth"
KEYS_URL = "https://openrouter.ai/api/v1/auth/keys"
ENV_VAR = "OPENROUTER_API_KEY"

# (url, json_payload) -> parsed json response. Injectable so tests need no network.
HttpPost = Callable[[str, dict[str, Any]], dict[str, Any]]


# --- PKCE primitives (RFC 7636) ---------------------------------------------


def generate_verifier(n_bytes: int = 64) -> str:
    """A high-entropy PKCE code_verifier (43-128 url-safe chars per RFC 7636)."""
    return secrets.token_urlsafe(n_bytes)


def challenge_s256(verifier: str) -> str:
    """base64url(sha256(verifier)), unpadded — the S256 code_challenge."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_auth_url(callback_url: str, code_challenge: str) -> str:
    query = urlencode(
        {
            "callback_url": callback_url,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{AUTH_URL}?{query}"


# --- Code -> key exchange ---------------------------------------------------


def _urllib_post(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    req = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https endpoint
        return json.loads(resp.read())


def exchange_code(code: str, verifier: str, http_post: HttpPost | None = None) -> str:
    """Exchange the authorization code for a user-controlled API key."""
    post = http_post or _urllib_post
    body = {"code": code, "code_verifier": verifier, "code_challenge_method": "S256"}
    resp = post(KEYS_URL, body)
    key = resp.get("key")
    if not key:
        raise RuntimeError(f"OpenRouter returned no key (response: {resp!r})")
    return key


# --- .env write -------------------------------------------------------------


def upsert_env_var(text: str, key: str, value: str) -> str:
    """Return ``text`` with ``key=value`` set: replace the existing line if present,
    otherwise append it. Other lines are preserved untouched."""
    line = f"{key}={value}"
    out: list[str] = []
    replaced = False
    for raw in text.splitlines():
        stripped = raw.lstrip()
        if stripped.startswith(f"{key}=") or stripped.startswith(f"{key} ="):
            out.append(line)
            replaced = True
        else:
            out.append(raw)
    if not replaced:
        out.append(line)
    return "\n".join(out) + "\n"


def write_env(key: str, path: str = ".env", var: str = ENV_VAR) -> None:
    p = Path(path)
    existing = p.read_text(encoding="utf-8") if p.exists() else ""
    p.write_text(upsert_env_var(existing, var, key), encoding="utf-8")


# --- Browser flow -----------------------------------------------------------


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        code = parse_qs(urlparse(self.path).query).get("code", [None])[0]
        if code:
            self.server.captured_code = code  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = (
            b"<h1>SecForge: authorization received.</h1><p>You can close this tab.</p>"
            if code
            else b"<h1>SecForge: no code in callback.</h1>"
        )
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def capture_code(server: HTTPServer) -> str | None:
    """Serve callback requests until one carries a ``code`` (ignores e.g. favicon hits)."""
    server.captured_code = None  # type: ignore[attr-defined]
    while server.captured_code is None:  # type: ignore[attr-defined]
        server.handle_request()
    return server.captured_code  # type: ignore[attr-defined]


def main() -> None:
    verifier = generate_verifier()
    challenge = challenge_s256(verifier)

    server = HTTPServer(("127.0.0.1", 0), _CallbackHandler)
    port = server.server_address[1]
    callback_url = f"http://localhost:{port}/callback"
    auth_url = build_auth_url(callback_url, challenge)

    print("Opening OpenRouter authorization in your browser...")
    print(f"If it does not open, visit this URL manually:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    code = capture_code(server)
    server.server_close()
    if not code:
        raise SystemExit("No authorization code received.")

    print("Authorization received; exchanging the code for an API key...")
    key = exchange_code(code, verifier)
    write_env(key)
    print(f"Saved {ENV_VAR} to .env.")
    print("Use it with:  SECFORGE_MODEL_BACKEND=openrouter   (or  --backend openrouter)")


if __name__ == "__main__":
    main()
