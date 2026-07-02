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
    # A broad multi-provider catalogue across every category, plus both escape hatches. API-key
    # providers are pruned to Anthropic + OpenAI only — everything else free/no-signup lives in
    # the free-tier category instead (opencode, openrouter, gemini-cli, kiro, ...).
    assert {"anthropic", "openai"} <= ids  # apikey (bring your own key)
    assert {"openrouter", "opencode", "gemini-cli", "kiro"} <= ids  # free tier
    assert {"claude-code", "github-copilot", "codex", "cursor"} <= ids  # oauth sign-in
    assert {"ollama", "9router", "antigravity"} <= ids  # local & private
    assert {"openai-compat", "anthropic-compat"} <= ids  # custom escape hatches


def test_apikey_category_is_pruned_to_anthropic_and_openai():
    apikey_ids = {p["id"] for p in PROVIDER_TYPES if p["category"] == "apikey"}
    assert apikey_ids == {"anthropic", "openai"}


def test_gemini_cli_and_kiro_are_free_tier_not_oauth_signin():
    # Mirrors 9Router's own registry (open-sse/providers/registry/{gemini-cli,kiro}.js are both
    # `category: "free"`) — they grant a free consumer/AWS quota, not a paid subscription, so
    # they sit in the Free tier section rather than cluttering OAuth Providers.
    by_id = {p["id"]: p for p in PROVIDER_TYPES}
    for pid in ("gemini-cli", "kiro"):
        assert by_id[pid]["category"] == "free"
        assert by_id[pid]["auth"] == "oauth"


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


def test_check_endpoint_flags_401_as_auth_failure():
    r = check_endpoint("https://x/v1", "bad", http_post=lambda *a: (401, "invalid api key"))
    assert r["ok"] is False
    assert r["status"] == 401
    assert r["reason"] == "auth"


def test_check_endpoint_treats_429_as_rate_limited_not_bad_key():
    # A valid key that's throttled / out of quota must NOT read as a rejected credential — this is
    # the reported bug: "key is correct but Test shows Failed" (e.g. gemini-2.5-pro at limit 0).
    r = check_endpoint("https://x/v1", "good", http_post=lambda *a: (429, "rate limit exceeded"))
    assert r["ok"] is False
    assert r["status"] == 429
    assert r["reason"] == "rate_limited"


def test_check_endpoint_treats_bad_model_as_reachable_not_auth():
    # A 400/404 for a wrong model id means the endpoint answered past auth — key looks accepted.
    r = check_endpoint("https://x/v1", "good", "no", http_post=lambda *a: (404, "model not found"))
    assert r["ok"] is False
    assert r["status"] == 404
    assert r["reason"] == "reachable"


def test_check_endpoint_reads_a_400_bad_key_body_as_auth():
    # Google's OpenAI-compatible endpoint answers a *bad key* with 400, not 401 — trust the body.
    r = check_endpoint(
        "https://x/v1", "bad",
        http_post=lambda *a: (400, '{"error":{"message":"Please pass a valid API key"}}'),
    )
    assert r["ok"] is False
    assert r["status"] == 400
    assert r["reason"] == "auth"


def test_check_endpoint_treats_5xx_as_server_error_not_key():
    r = check_endpoint("https://x/v1", "good", http_post=lambda *a: (503, "upstream unavailable"))
    assert r["ok"] is False
    assert r["reason"] == "server"


def test_check_endpoint_transport_failure_carries_unreachable_reason():
    def boom(*_a):
        raise URLError("connection refused")

    r = check_endpoint("https://x/v1", http_post=boom)
    assert r["reason"] == "unreachable"


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


class _RateLimitedHandler(BaseHTTPRequestHandler):
    """A stand-in endpoint whose key is valid but is throttled — answers 429 to chat POSTs."""

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = b'{"error":{"message":"rate limit exceeded"}}'
        self.send_response(429)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def _serve(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def chat_server():
    server, thread = _serve(_ChatHandler)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def rate_limited_server():
    server, thread = _serve(_RateLimitedHandler)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
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


def _get(url):
    with urlopen(url) as resp:
        return resp.status, json.loads(resp.read())


def _post_patch(url, body):
    data = json.dumps(body).encode()
    with urlopen(Request(url, data=data, method="PATCH")) as resp:
        return resp.status, json.loads(resp.read())


def test_provider_types_route_returns_categorized_catalog(api):
    with urlopen(f"{api}/provider-types") as resp:
        catalog = json.loads(resp.read())
    assert any(p["id"] == "openai" and p["category"] == "apikey" for p in catalog)


def test_test_connection_route_probes_the_endpoint(api, chat_server):
    status, body = _post(f"{api}/test-connection", {"base_url": chat_server})
    assert status == 200
    assert body == {"ok": True, "status": 200}


def test_test_connection_route_carries_reason_for_a_rate_limited_key(api, rate_limited_server):
    # End-to-end: a valid-but-throttled key (429) reaches the UI as rate_limited, not a hard fail,
    # so the "key is correct but Test shows Failed" report can't recur through the HTTP path.
    payload = {"base_url": rate_limited_server, "api_key": "k"}
    status, body = _post(f"{api}/test-connection", payload)
    assert status == 200
    assert body["ok"] is False
    assert body["status"] == 429
    assert body["reason"] == "rate_limited"


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


# ── settings menu: quota / import-export / models routes ──
def test_usage_route_lists_accounts_with_limits_and_zeroed_counters(api):
    _, account = _post(f"{api}/accounts", {"label": "oai", "base_url": "https://x/v1"})
    _post_patch(f"{api}/accounts/{account['id']}", {"quota_daily_requests": 500})

    status, body = _get(f"{api}/usage")
    assert status == 200
    row = next(a for a in body["accounts"] if a["id"] == account["id"])
    assert row["limits"]["daily_requests"] == 500
    assert row["total"].get("calls", 0) == 0  # nothing recorded yet


def test_usage_reset_route_is_ok(api):
    status, body = _post(f"{api}/usage/reset", {})
    assert status == 200 and body == {"ok": True}


def test_export_masks_keys_by_default_and_includes_them_on_request(api):
    _post(f"{api}/accounts", {"label": "oai", "base_url": "https://x/v1", "api_key": "sk-secret"})

    _, masked = _get(f"{api}/accounts/export")
    assert masked["accounts"][0]["api_key"] == ""  # scrubbed unless asked

    _, full = _get(f"{api}/accounts/export?include_keys=1")
    assert full["accounts"][0]["api_key"] == "sk-secret"


def test_import_adds_new_accounts_and_dedupes_on_repeat(api):
    rows = [{"label": "imported", "base_url": "https://y/v1", "kind": "openai"}]

    _, first = _post(f"{api}/accounts/import", {"accounts": rows, "mode": "merge"})
    assert first == {"added": 1, "skipped": 0}

    _, second = _post(f"{api}/accounts/import", {"accounts": rows, "mode": "merge"})
    assert second == {"added": 0, "skipped": 1}  # same (kind, base_url, label) → deduped


def test_import_replace_clears_the_existing_pool_first(api):
    _post(f"{api}/accounts", {"label": "old", "base_url": "https://old/v1"})
    rows = [{"label": "fresh", "base_url": "https://new/v1"}]

    _, result = _post(f"{api}/accounts/import", {"accounts": rows, "mode": "replace"})
    assert result["added"] == 1

    _, view = _get(f"{api}/accounts")
    labels = {a["label"] for a in view["accounts"]}
    assert labels == {"fresh"}  # the old account was cleared


def test_import_rejects_a_non_list_accounts_field(api):
    import urllib.error

    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{api}/accounts/import", {"accounts": "not-a-list"})
    assert exc.value.code == 400


def test_models_route_returns_accounts_and_catalog(api):
    _post(f"{api}/accounts", {"label": "oai", "base_url": "https://x/v1", "model": "gpt-4o-mini"})
    status, body = _get(f"{api}/models")
    assert status == 200
    assert any(a["label"] == "oai" for a in body["accounts"])
    assert any(c["provider"] == "openai" and c["models"] for c in body["catalog"])
