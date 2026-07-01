"""Provider catalog + live connection test, and the API routes that expose them."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import URLError
from urllib.request import Request, urlopen

import pytest

from ai_framework.router.accounts import AccountStore
from backend.app import make_handler
from backend.providers import CATEGORIES, PROVIDER_TYPES, check_endpoint
from backend.service import RunService

REQUIRED = {
    "id", "label", "category", "base_url", "default_model", "models", "tier", "auth", "private",
    "api_style", "flow", "risk", "note",
}


# ── catalog shape ──
def test_every_preset_has_the_required_fields():
    for p in PROVIDER_TYPES:
        assert REQUIRED <= set(p), f"{p.get('id')} missing {REQUIRED - set(p)}"
        assert p["category"] in CATEGORIES
        assert p["auth"] in {"key", "none", "oauth"}
        assert p["api_style"] in {"openai", "anthropic", "openai-responses", "cursor",
                                  "gemini-cli", "kiro"}


def test_provider_ids_are_unique_and_every_category_is_populated():
    ids = [p["id"] for p in PROVIDER_TYPES]
    assert len(ids) == len(set(ids))
    populated = {p["category"] for p in PROVIDER_TYPES}
    assert populated == set(CATEGORIES)


def test_core_ids_present_and_custom_escape_hatch_exists():
    ids = {p["id"] for p in PROVIDER_TYPES}
    # A broad multi-provider catalogue across every category, plus both escape hatches.
    assert {"anthropic", "openai", "openrouter", "deepseek", "groq", "mistral"} <= ids  # key/free
    assert {"claude-code", "github-copilot", "codex", "cursor"} <= ids  # oauth sign-in
    assert {"ollama", "9router", "antigravity"} <= ids  # local & private
    assert {"openai-compat", "anthropic-compat"} <= ids  # custom escape hatches


def test_model_suggestions_are_wellformed():
    for p in PROVIDER_TYPES:
        assert isinstance(p["models"], list)
        assert all(isinstance(m, str) and m for m in p["models"]), p["id"]
        # When suggestions exist, the default model is one of them.
        if p["models"] and p["default_model"]:
            assert p["default_model"] in p["models"], p["id"]


def test_antigravity_matches_the_manager_proxy():
    ag = next(p for p in PROVIDER_TYPES if p["id"] == "antigravity")
    assert ag["base_url"] == "http://localhost:8045/v1"  # Antigravity-Manager default port
    assert ag["auth"] == "none" and ag["private"] is True
    assert {"gemini-3-pro-high", "claude-sonnet-4-6", "gpt-oss-120b-medium"} <= set(ag["models"])


def test_oauth_providers_declare_a_flow_and_apikey_providers_do_not():
    for p in PROVIDER_TYPES:
        if p["auth"] == "oauth":
            assert p["flow"] in {"device", "pkce"}, p["id"]
        else:
            assert p["flow"] == "", p["id"]


def test_local_providers_are_private_and_keyless():
    for p in PROVIDER_TYPES:
        if p["category"] == "local":
            assert p["private"] is True
            assert p["auth"] == "none"


# ── check_endpoint (injected poster → no network) ──
def test_check_endpoint_reports_ok_on_2xx():
    r = check_endpoint("https://x/v1", "k", "m", http_post=lambda *a: (200, "{}"))
    assert r == {"ok": True, "status": 200}


def test_check_endpoint_surfaces_http_error_status_and_body():
    r = check_endpoint("https://x/v1", "bad", http_post=lambda *a: (401, "invalid key"))
    assert r["ok"] is False
    assert r["status"] == 401
    assert "invalid key" in r["error"]


def test_check_endpoint_treats_transport_failure_as_unreachable():
    def boom(*_a):
        raise URLError("connection refused")

    r = check_endpoint("https://x/v1", http_post=boom)
    assert r["ok"] is False
    assert r["status"] == 0
    assert "refused" in r["error"]


def test_check_endpoint_rejects_empty_base_url():
    r = check_endpoint("", "k")
    assert r["ok"] is False and r["status"] == 0


def test_check_endpoint_uses_anthropic_shape_when_asked():
    seen = {}

    def capture(url, payload, headers, timeout):
        seen["url"] = url
        seen["headers"] = headers
        return 200, "{}"

    r = check_endpoint("https://x/v1", "k", "claude-x", api_style="anthropic", http_post=capture)
    assert r == {"ok": True, "status": 200}
    assert seen["url"].endswith("/messages")  # not /chat/completions
    assert seen["headers"]["x-api-key"] == "k"
    assert "anthropic-version" in seen["headers"]


# ── API routes ──
class _ChatHandler(BaseHTTPRequestHandler):
    """A stand-in OpenAI-compatible endpoint: drains the body, answers 200 to chat POSTs."""

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = b'{"choices":[{"message":{"content":"pong"}}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def chat_server():
    server = HTTPServer(("127.0.0.1", 0), _ChatHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://127.0.0.1:{port}/v1"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def api(tmp_path):
    accounts = AccountStore(path=str(tmp_path / "accounts.json"))
    service = RunService(memory_path=str(tmp_path / "mem.jsonl"), accounts=accounts)
    server = HTTPServer(("127.0.0.1", 0), make_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join()


def _post(url, body):
    data = json.dumps(body).encode()
    with urlopen(Request(url, data=data, method="POST")) as resp:
        return resp.status, json.loads(resp.read())


def test_provider_types_route_returns_categorized_catalog(api):
    with urlopen(f"{api}/provider-types") as resp:
        catalog = json.loads(resp.read())
    assert any(p["id"] == "openai" and p["category"] == "apikey" for p in catalog)


def test_test_connection_route_probes_the_endpoint(api, chat_server):
    status, body = _post(f"{api}/test-connection", {"base_url": chat_server})
    assert status == 200
    assert body == {"ok": True, "status": 200}


def test_account_test_route_uses_the_stored_endpoint(api, chat_server):
    _, account = _post(f"{api}/accounts", {"label": "mock", "base_url": chat_server})
    status, body = _post(f"{api}/accounts/{account['id']}/test", {})
    assert status == 200
    assert body == {"ok": True, "status": 200}


def test_account_test_route_404s_on_unknown_id(api):
    import urllib.error

    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{api}/accounts/nope/test", {})
    assert exc.value.code == 404
