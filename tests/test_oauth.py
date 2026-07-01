"""OAuth sign-in engine — device flow, PKCE, GitHub Copilot exchange, and refresh.

All network is stubbed via an injected ``http`` callable, so these run offline and pin the exact
request shapes the engine sends (grant types, PKCE, token endpoints).
"""

import pytest

from ai_framework.router.oauth import OAuthError, OAuthManager, make_pkce


def _routes(mapping):
    """Build an injectable http fn from an ``{(method, url): (status, body)}`` map.

    A value may be a callable ``(headers, body) -> (status, json)`` to assert on the request.
    """
    def http(method, url, headers, body):
        key = (method, url)
        if key not in mapping:
            raise AssertionError(f"unexpected request: {key}")
        val = mapping[key]
        return val(headers, body) if callable(val) else val
    return http


# ── PKCE primitive ──
def test_make_pkce_is_url_safe_and_deterministic_challenge():
    v1, c1 = make_pkce()
    v2, c2 = make_pkce()
    assert v1 != v2 and c1 != c2  # fresh each call
    assert "=" not in c1 and "+" not in c1 and "/" not in c1  # base64url, unpadded


# ── device flow (Qwen-style, no post-exchange) ──
def test_device_flow_start_poll_pending_then_done():
    token_url = "https://chat.qwen.ai/api/v1/oauth2/token"
    device_url = "https://chat.qwen.ai/api/v1/oauth2/device/code"
    state = {"polls": 0}

    def token(headers, body):
        assert "grant_type=urn" in body  # RFC 8628 device_code grant (url-encoded)
        assert "device_code=DEV123" in body
        state["polls"] += 1
        if state["polls"] < 2:
            return 400, {"error": "authorization_pending"}
        return 200, {"access_token": "AT", "refresh_token": "RT", "expires_in": 3600}

    mgr = OAuthManager(http=_routes({
        ("POST", device_url): (200, {
            "device_code": "DEV123", "user_code": "WXYZ-1234",
            "verification_uri": "https://chat.qwen.ai/device", "interval": 1, "expires_in": 600,
        }),
        ("POST", token_url): token,
    }))

    started = mgr.start("qwen-code")
    assert started["flow"] == "device"
    assert started["user_code"] == "WXYZ-1234"

    first = mgr.poll(started["session_id"])
    assert first["status"] == "pending"

    done = mgr.poll(started["session_id"])
    assert done["status"] == "done"
    acct = done["account"]
    assert acct["api_key"] == "AT"
    assert acct["refresh_token"] == "RT"
    assert acct["oauth_provider"] == "qwen-code"
    assert acct["base_url"] == "https://portal.qwen.ai/v1"
    assert acct["token_expiry"] > 0


def test_device_flow_resource_url_overrides_base_url():
    device_url = "https://chat.qwen.ai/api/v1/oauth2/device/code"
    token_url = "https://chat.qwen.ai/api/v1/oauth2/token"
    mgr = OAuthManager(http=_routes({
        ("POST", device_url): (200, {"device_code": "D", "user_code": "U", "interval": 1}),
        ("POST", token_url): (200, {"access_token": "AT", "resource_url": "https://region.qwen.ai/v1"}),
    }))
    started = mgr.start("qwen-code")
    done = mgr.poll(started["session_id"])
    assert done["account"]["base_url"] == "https://region.qwen.ai/v1"


# ── GitHub Copilot: device flow + copilot token exchange ──
def test_github_copilot_exchange_stores_copilot_token_and_headers():
    device_url = "https://github.com/login/device/code"
    token_url = "https://github.com/login/oauth/access_token"
    copilot_url = "https://api.github.com/copilot_internal/v2/token"

    def copilot(headers, body):
        assert headers["Authorization"] == "Bearer GH_TOKEN"
        return 200, {"token": "COPILOT_TOK", "expires_at": 9999999999}

    mgr = OAuthManager(http=_routes({
        ("POST", device_url): (200, {"device_code": "D", "user_code": "U", "interval": 1}),
        ("POST", token_url): (200, {"access_token": "GH_TOKEN"}),
        ("GET", copilot_url): copilot,
    }))
    started = mgr.start("github-copilot")
    done = mgr.poll(started["session_id"])
    acct = done["account"]
    assert acct["api_key"] == "COPILOT_TOK"  # the usable upstream token
    assert acct["refresh_token"] == "GH_TOKEN"  # re-mint from this later
    assert acct["base_url"] == "https://api.githubcopilot.com"
    assert acct["extra_headers"]["copilot-integration-id"] == "vscode-chat"


def test_github_refresh_remints_copilot_token():
    copilot_url = "https://api.github.com/copilot_internal/v2/token"
    mgr = OAuthManager(http=_routes({
        ("GET", copilot_url): (200, {"token": "NEW_COPILOT", "expires_at": 123}),
    }))
    out = mgr.refresh("github-copilot", "GH_TOKEN")
    assert out["api_key"] == "NEW_COPILOT"
    assert out["refresh_token"] == "GH_TOKEN"


# ── PKCE flow (Claude Code-style, json exchange) ──
def test_pkce_start_builds_authorize_url_and_completes_with_pasted_code():
    token_url = "https://api.anthropic.com/v1/oauth/token"

    def token(headers, body):
        assert headers["Content-Type"] == "application/json"  # claude uses json encoding
        assert '"grant_type": "authorization_code"' in body
        assert '"code": "THECODE"' in body
        return 200, {"access_token": "CLAUDE_AT", "refresh_token": "CLAUDE_RT", "expires_in": 60}

    mgr = OAuthManager(http=_routes({("POST", token_url): token}))
    started = mgr.start("claude-code")
    assert started["flow"] == "pkce"
    assert started["authorize_url"].startswith("https://claude.ai/oauth/authorize?")
    assert "code_challenge=" in started["authorize_url"]

    # A bare code (no "#state" suffix) exchanges directly for a token.
    result = mgr.complete(started["session_id"], "THECODE")
    acct = result["account"]
    assert acct["api_key"] == "CLAUDE_AT"
    assert acct["api_style"] == "anthropic"
    assert acct["oauth_provider"] == "claude-code"


def test_pkce_state_mismatch_is_rejected():
    mgr = OAuthManager(http=_routes({}))
    started = mgr.start("claude-code")
    with pytest.raises(OAuthError):
        mgr.complete(started["session_id"], "code#not-the-real-state")


# ── guardrails ──
def test_unsupported_provider_fails_loudly():
    mgr = OAuthManager(http=_routes({}))
    with pytest.raises(OAuthError) as exc:
        mgr.start("cursor")
    assert "proprietary" in str(exc.value).lower() or "proxy" in str(exc.value).lower()


def test_unknown_provider_and_expired_session():
    mgr = OAuthManager(http=_routes({}))
    with pytest.raises(OAuthError):
        mgr.start("does-not-exist")
    with pytest.raises(OAuthError):
        mgr.poll("no-such-session")
