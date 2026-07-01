"""OAuth sign-in engine for provider connections — stdlib only, injectable for tests.

Some providers are reached not with a pasted API key but with a subscription/session token
obtained through an OAuth flow. This module runs those flows *inside SecForge* and hands the
account store a ready-to-use bearer token — the same shape every other connection uses
(:mod:`ai_framework.router.accounts`), so the rest of the stack is unchanged.

Two standard flows are implemented generically:

* **Device authorization** (RFC 8628) — the UI shows a ``user_code`` + verification URL; we poll
  the token endpoint until the user approves. Used by GitHub Copilot, Qwen, Kimi Coding.
* **Authorization code + PKCE** (RFC 7636) — the UI opens the provider's authorize URL; the user
  signs in and pastes back the returned ``code`` (loopback/paste style), which we exchange for a
  token. Used by Claude Code, Codex, Cline, Gemini CLI.

Provider client ids / endpoints below are the public values a working router uses. They are
credentials for a *client application*, not for any user account, and change over time — treat
this registry as configuration, not as a promise. Providers whose real API is not an
OpenAI/Anthropic chat shape (Cursor's protobuf, Kiro's AWS-SSO, Kilo's custom device) are
registered but marked ``supported=False`` so the flow fails loudly instead of pretending.

⚠️ Risk: using a subscription/OAuth session through a router is generally *not* licensed by the
vendor. The account may be rate-limited or banned. The catalog marks these ``risk`` and the UI
warns before connecting. Only sign in to accounts you are authorized to use this way.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

# GitHub Copilot needs the editor headers on every upstream call; stored on the account so the
# OpenAI backend replays them. Sourced from the 9Router github registry entry.
COPILOT_HEADERS: dict[str, str] = {
    "copilot-integration-id": "vscode-chat",
    "editor-version": "vscode/1.110.0",
    "editor-plugin-version": "copilot-chat/0.38.0",
    "user-agent": "GitHubCopilotChat/0.38.0",
    "openai-intent": "conversation-panel",
    "x-github-api-version": "2025-04-01",
}


@dataclass(frozen=True)
class OAuthProvider:
    """Static config for one provider's OAuth flow (see module docstring)."""

    id: str
    flow: str  # "device" | "pkce"
    client_id: str = ""
    client_secret: str = ""
    authorize_url: str = ""
    token_url: str = ""
    device_code_url: str = ""
    refresh_url: str = ""
    scopes: str = ""  # space-separated
    use_pkce: bool = False
    code_challenge_method: str = "S256"
    exchange_encoding: str = "form"  # "form" | "json"
    refresh_encoding: str = "form"
    redirect_uri: str = ""  # for pkce; empty => manual/loopback paste
    extra_authorize_params: dict[str, str] = field(default_factory=dict)
    # What the resulting account looks like (merged with catalog defaults by the API layer).
    base_url: str = ""
    api_style: str = "openai"
    tier: str = "subscription"
    default_model: str = ""
    account_headers: dict[str, str] = field(default_factory=dict)
    post_exchange: str = ""  # name of a special step, e.g. "github_copilot"
    supported: bool = True
    unsupported_reason: str = ""


# Accurate values mirrored from the 9Router provider registry (open-sse/providers/registry/*).
PROVIDERS: dict[str, OAuthProvider] = {
    "github-copilot": OAuthProvider(
        id="github-copilot",
        flow="device",
        client_id="Iv1.b507a08c87ecfe98",
        device_code_url="https://github.com/login/device/code",
        token_url="https://github.com/login/oauth/access_token",
        refresh_url="https://github.com/login/oauth/access_token",
        scopes="read:user",
        base_url="https://api.githubcopilot.com",
        api_style="openai",
        default_model="gpt-5.4",
        account_headers=dict(COPILOT_HEADERS),
        post_exchange="github_copilot",
    ),
    "qwen-code": OAuthProvider(
        id="qwen-code",
        flow="device",
        client_id="f0304373b74a44d2b584a3fb70ca9e56",
        device_code_url="https://chat.qwen.ai/api/v1/oauth2/device/code",
        token_url="https://chat.qwen.ai/api/v1/oauth2/token",
        refresh_url="https://chat.qwen.ai/api/v1/oauth2/token",
        scopes="openid profile email model.completion",
        use_pkce=True,
        base_url="https://portal.qwen.ai/v1",
        default_model="qwen3-coder-plus",
        tier="free",
    ),
    "kimi-coding": OAuthProvider(
        id="kimi-coding",
        flow="device",
        client_id="17e5f671-d194-4dfb-9706-5516cb48c098",
        device_code_url="https://auth.kimi.com/api/oauth/device_authorization",
        token_url="https://auth.kimi.com/api/oauth/token",
        refresh_url="https://auth.kimi.com/api/oauth/token",
        base_url="https://api.kimi.com/coding/v1",
        api_style="anthropic",
        default_model="kimi-k2.5",
    ),
    "claude-code": OAuthProvider(
        id="claude-code",
        flow="pkce",
        client_id="9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        authorize_url="https://claude.ai/oauth/authorize",
        token_url="https://api.anthropic.com/v1/oauth/token",
        refresh_url="https://api.anthropic.com/v1/oauth/token",
        scopes="org:create_api_key user:profile user:inference",
        use_pkce=True,
        exchange_encoding="json",
        refresh_encoding="json",
        redirect_uri="https://console.anthropic.com/oauth/code/callback",
        base_url="https://api.anthropic.com/v1",
        api_style="anthropic",
        default_model="claude-sonnet-4-6",
    ),
    "codex": OAuthProvider(
        id="codex",
        flow="pkce",
        client_id="app_EMoamEEZ73f0CkXaXp7hrann",
        authorize_url="https://auth.openai.com/oauth/authorize",
        token_url="https://auth.openai.com/oauth/token",
        refresh_url="https://auth.openai.com/oauth/token",
        scopes="openid profile email offline_access",
        use_pkce=True,
        redirect_uri="http://localhost:1455/auth/callback",
        extra_authorize_params={
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
            "originator": "codex_cli_rs",
        },
        base_url="https://chatgpt.com/backend-api/codex",
        api_style="openai-responses",
        default_model="gpt-5.3-codex",
    ),
    "cline": OAuthProvider(
        id="cline",
        flow="pkce",
        authorize_url="https://api.cline.bot/api/v1/auth/authorize",
        token_url="https://api.cline.bot/api/v1/auth/token",
        refresh_url="https://api.cline.bot/api/v1/auth/refresh",
        use_pkce=True,
        redirect_uri="https://app.cline.bot/auth/callback",
        base_url="https://api.cline.bot/api/v1",
        default_model="anthropic/claude-sonnet-4.6",
    ),
    "gemini-cli": OAuthProvider(
        id="gemini-cli",
        flow="pkce",
        # Google flags OAuth client id/secret as secrets and blocks them in git. Supply the
        # Gemini CLI client credentials via env (SECFORGE_GEMINI_CLIENT_ID / _SECRET); empty
        # until then, so the flow stays disabled rather than shipping a credential in the repo.
        client_id=os.environ.get("SECFORGE_GEMINI_CLIENT_ID", ""),
        client_secret=os.environ.get("SECFORGE_GEMINI_CLIENT_SECRET", ""),
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        refresh_url="https://oauth2.googleapis.com/token",
        scopes=(
            "https://www.googleapis.com/auth/cloud-platform "
            "https://www.googleapis.com/auth/userinfo.email "
            "https://www.googleapis.com/auth/userinfo.profile"
        ),
        use_pkce=True,
        redirect_uri="http://localhost:8085/oauth2callback",
        extra_authorize_params={"access_type": "offline", "prompt": "consent"},
        base_url="https://cloudcode-pa.googleapis.com/v1internal",
        api_style="gemini-cli",
        default_model="gemini-2.5-pro",
        tier="free",
    ),
    # Registered but not drivable by SecForge's chat loop yet — fail loudly, don't fake it.
    "cursor": OAuthProvider(
        id="cursor", flow="pkce", supported=False,
        unsupported_reason="Cursor uses a proprietary protobuf API that SecForge cannot speak. "
        "Use it through the local 9Router/Antigravity proxy instead.",
    ),
    "kiro": OAuthProvider(
        id="kiro", flow="device", supported=False,
        unsupported_reason="Kiro uses AWS SSO OIDC with per-region client registration. "
        "Sign in via the Kiro app and route through the local proxy.",
    ),
    "kilo-code": OAuthProvider(
        id="kilo-code", flow="device",
        device_code_url="https://api.kilo.ai/api/device-auth/codes",
        token_url="https://api.kilo.ai/api/device-auth/codes",
        base_url="https://api.kilo.ai/api/openrouter",
        default_model="anthropic/claude-sonnet-4-20250514",
        supported=False,
        unsupported_reason="Kilo Code uses a non-standard device endpoint; wiring it needs the "
        "exact poll contract. Not enabled yet.",
    ),
}


class OAuthError(Exception):
    """A flow-level failure with a human-readable message."""


# (method, url, headers, body) -> (status, parsed_json_or_text). Injectable so tests need no net.
HttpFn = Callable[[str, str, dict[str, str], str | None], tuple[int, Any]]


def _default_http(
    method: str, url: str, headers: dict[str, str], body: str | None
) -> tuple[int, Any]:
    data = body.encode() if body is not None else None
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as resp:  # noqa: S310 - endpoints come from this registry
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except HTTPError as exc:
        raw = ""
        try:
            raw = exc.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        status = exc.code
    except (URLError, OSError) as exc:
        raise OAuthError(f"network error: {getattr(exc, 'reason', exc)}") from exc
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


# ── PKCE helpers (RFC 7636) ──
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` using S256."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def _form(fields: dict[str, str]) -> str:
    return urlencode({k: v for k, v in fields.items() if v})


def _encode_body(encoding: str, fields: dict[str, str]) -> tuple[str, str]:
    """Return ``(content_type, body)`` for a token request."""
    clean = {k: v for k, v in fields.items() if v}
    if encoding == "json":
        return "application/json", json.dumps(clean)
    return "application/x-www-form-urlencoded", _form(clean)


class OAuthManager:
    """Runs sign-in flows and holds pending sessions in-process (local single-user tool)."""

    def __init__(self, http: HttpFn | None = None) -> None:
        self._http = http or _default_http
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    # ── public listing (for the UI) ──
    @staticmethod
    def provider(provider_id: str) -> OAuthProvider | None:
        return PROVIDERS.get(provider_id)

    # ── start ──
    def start(self, provider_id: str) -> dict[str, Any]:
        p = PROVIDERS.get(provider_id)
        if p is None:
            raise OAuthError(f"unknown OAuth provider: {provider_id}")
        if not p.supported:
            raise OAuthError(p.unsupported_reason or "this provider is not supported yet")
        if p.id == "gemini-cli" and not p.client_id:
            raise OAuthError(
                "Gemini CLI needs Google OAuth client credentials — set "
                "SECFORGE_GEMINI_CLIENT_ID and SECFORGE_GEMINI_CLIENT_SECRET, then retry."
            )
        return self._start_device(p) if p.flow == "device" else self._start_pkce(p)

    def _new_session(self, data: dict[str, Any]) -> str:
        sid = secrets.token_urlsafe(12)
        with self._lock:
            self._sessions[sid] = {**data, "created": time.time()}
        return sid

    def _start_device(self, p: OAuthProvider) -> dict[str, Any]:
        verifier = challenge = ""
        fields = {"client_id": p.client_id, "scope": p.scopes}
        if p.use_pkce:
            verifier, challenge = make_pkce()
            fields["code_challenge"] = challenge
            fields["code_challenge_method"] = p.code_challenge_method
        ctype, body = _encode_body("form", fields)
        status, data = self._http(
            "POST", p.device_code_url, {"Content-Type": ctype, "Accept": "application/json"}, body
        )
        if not isinstance(data, dict) or "device_code" not in data:
            raise OAuthError(f"device code request failed ({status}): {str(data)[:200]}")
        sid = self._new_session(
            {"provider": p.id, "flow": "device", "device_code": data["device_code"],
             "verifier": verifier, "interval": int(data.get("interval", 5))}
        )
        return {
            "session_id": sid,
            "flow": "device",
            "provider": p.id,
            "user_code": data.get("user_code", ""),
            "verification_uri": data.get("verification_uri") or data.get("verification_url", ""),
            "verification_uri_complete": data.get("verification_uri_complete", ""),
            "interval": int(data.get("interval", 5)),
            "expires_in": int(data.get("expires_in", 900)),
        }

    def _start_pkce(self, p: OAuthProvider) -> dict[str, Any]:
        verifier, challenge = make_pkce()
        state = secrets.token_urlsafe(24)
        params = {
            "client_id": p.client_id,
            "response_type": "code",
            "redirect_uri": p.redirect_uri,
            "scope": p.scopes,
            "state": state,
            **p.extra_authorize_params,
        }
        if p.use_pkce:
            params["code_challenge"] = challenge
            params["code_challenge_method"] = p.code_challenge_method
        authorize_url = f"{p.authorize_url}?{urlencode(params)}"
        sid = self._new_session(
            {"provider": p.id, "flow": "pkce", "verifier": verifier, "state": state}
        )
        return {
            "session_id": sid,
            "flow": "pkce",
            "provider": p.id,
            "authorize_url": authorize_url,
            "redirect_uri": p.redirect_uri,
        }

    # ── device poll ──
    def poll(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            sess = self._sessions.get(session_id)
        if not sess:
            raise OAuthError("unknown or expired session")
        p = PROVIDERS[sess["provider"]]
        fields = {
            "client_id": p.client_id,
            "device_code": sess["device_code"],
            "grant_type": DEVICE_GRANT,
        }
        if sess.get("verifier"):
            fields["code_verifier"] = sess["verifier"]
        if p.client_secret:
            fields["client_secret"] = p.client_secret
        ctype, body = _encode_body("form", fields)
        status, data = self._http(
            "POST", p.token_url, {"Content-Type": ctype, "Accept": "application/json"}, body
        )
        if isinstance(data, dict) and data.get("access_token"):
            account = self._finalize(p, data)
            with self._lock:
                self._sessions.pop(session_id, None)
            return {"status": "done", "account": account}
        err = data.get("error") if isinstance(data, dict) else str(data)
        if err in {"authorization_pending", "slow_down"}:
            return {"status": "pending", "interval": sess["interval"], "error": err}
        raise OAuthError(f"authorization failed ({status}): {err or str(data)[:200]}")

    # ── pkce completion (user pasted the returned code) ──
    def complete(self, session_id: str, code: str) -> dict[str, Any]:
        with self._lock:
            sess = self._sessions.get(session_id)
        if not sess:
            raise OAuthError("unknown or expired session")
        # Providers append "#state" to the pasted code; split it off and verify.
        code = code.strip()
        if "#" in code:
            code, _, state = code.partition("#")
            if state and state != sess.get("state"):
                raise OAuthError("state mismatch — restart the sign-in")
        p = PROVIDERS[sess["provider"]]
        fields = {
            "grant_type": "authorization_code",
            "client_id": p.client_id,
            "client_secret": p.client_secret,
            "code": code,
            "redirect_uri": p.redirect_uri,
            "code_verifier": sess.get("verifier", ""),
        }
        ctype, body = _encode_body(p.exchange_encoding, fields)
        status, data = self._http(
            "POST", p.token_url, {"Content-Type": ctype, "Accept": "application/json"}, body
        )
        if not (isinstance(data, dict) and data.get("access_token")):
            err = data.get("error_description") if isinstance(data, dict) else str(data)
            raise OAuthError(f"token exchange failed ({status}): {err or str(data)[:200]}")
        account = self._finalize(p, data)
        with self._lock:
            self._sessions.pop(session_id, None)
        return {"status": "done", "account": account}

    # ── refresh (called by the router when a token is near expiry) ──
    def refresh(self, provider_id: str, refresh_token: str) -> dict[str, Any]:
        p = PROVIDERS.get(provider_id)
        if p is None:
            raise OAuthError(f"unknown OAuth provider: {provider_id}")
        if p.post_exchange == "github_copilot":
            # GitHub's device token is long-lived; the short-lived Copilot token is re-minted
            # from it. We stored the GitHub token as the refresh token.
            return self._github_copilot(refresh_token)
        fields = {
            "grant_type": "refresh_token",
            "client_id": p.client_id,
            "client_secret": p.client_secret,
            "refresh_token": refresh_token,
        }
        ctype, body = _encode_body(p.refresh_encoding, fields)
        status, data = self._http(
            "POST", p.refresh_url or p.token_url,
            {"Content-Type": ctype, "Accept": "application/json"}, body,
        )
        if not (isinstance(data, dict) and data.get("access_token")):
            raise OAuthError(f"token refresh failed ({status})")
        return {
            "api_key": data["access_token"],
            "refresh_token": data.get("refresh_token") or refresh_token,
            "token_expiry": _expiry(data.get("expires_in")),
        }

    # ── shared: turn a token response into account fields ──
    def _finalize(self, p: OAuthProvider, tokens: dict[str, Any]) -> dict[str, Any]:
        access = tokens["access_token"]
        refresh = tokens.get("refresh_token", "")
        base_url = p.base_url
        # Qwen returns the region endpoint to actually call.
        resource = tokens.get("resource_url")
        if resource:
            base_url = resource if resource.startswith("http") else f"https://{resource}/v1"
        account = {
            "kind": p.id,
            "base_url": base_url,
            "api_key": access,
            "model": p.default_model,
            "tier": p.tier,
            "api_style": p.api_style,
            "oauth_provider": p.id,
            "refresh_token": refresh,
            "token_expiry": _expiry(tokens.get("expires_in")),
            "extra_headers": dict(p.account_headers),
        }
        if p.post_exchange == "github_copilot":
            minted = self._github_copilot(access)
            account["api_key"] = minted["api_key"]
            account["refresh_token"] = access  # re-mint the Copilot token from this later
            account["token_expiry"] = minted["token_expiry"]
        return account

    def _github_copilot(self, github_token: str) -> dict[str, Any]:
        """Exchange a GitHub access token for a short-lived Copilot API token."""
        status, data = self._http(
            "GET",
            "https://api.github.com/copilot_internal/v2/token",
            {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "GitHubCopilotChat/0.26.7",
            },
            None,
        )
        if not (isinstance(data, dict) and data.get("token")):
            raise OAuthError(f"Copilot token exchange failed ({status})")
        return {
            "api_key": data["token"],
            "refresh_token": github_token,
            "token_expiry": float(data.get("expires_at", 0) or 0),
        }


def _expiry(expires_in: Any) -> float:
    """Absolute epoch seconds a token expires, or 0 when unknown/no expiry."""
    try:
        secs = int(expires_in)
    except (TypeError, ValueError):
        return 0.0
    return time.time() + secs if secs > 0 else 0.0
