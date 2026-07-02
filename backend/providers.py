"""Provider catalog for the Providers page — what runs the SecForge agent.

A "connection" here is the agent's fuel: one endpoint (``base_url`` + credential + model,
see :mod:`ai_framework.router.accounts`) that the Hermes loop, Defense review, and VI
translation all run on. Every connection ends up as an OpenAI- or Anthropic-shaped HTTP call,
so a diverse set of vendors collapses onto two wire formats (``api_style``).

This catalog mirrors the breadth of a full multi-provider router (the shape 9Router exposes)
but is *built for SecForge's own architecture* — no proprietary proxy in the middle, credentials
live in SecForge's own account store, and every entry is either a direct HTTP endpoint or a
real OAuth sign-in handled by :mod:`ai_framework.router.oauth`.

Catalog axes:

* ``category`` — how the UI groups the card:
    - ``oauth``  — sign in with a subscription/session (device-code or browser PKCE flow).
    - ``free``   — free-tier or keyless hosted endpoints.
    - ``apikey`` — bring an API key.
    - ``local``  — runs on your own machine; ``private`` so target data never leaves the box.
    - ``custom`` — any OpenAI- or Anthropic-compatible URL you point at (the escape hatch).
* ``api_style`` — ``openai`` (``/chat/completions``) or ``anthropic`` (``/messages``). The
  router picks the matching backend per account.
* ``auth`` — ``key`` (send a Bearer/x-api-key), ``none`` (local/keyless), or ``oauth``
  (SecForge runs the sign-in flow and stores the resulting access token as the account key).
* ``flow`` — for ``oauth`` entries only: ``device`` (RFC 8628) or ``pkce`` (RFC 7636). The
  concrete client ids / endpoints live in :mod:`ai_framework.router.oauth`.
* ``risk`` — true for subscription/OAuth sessions not officially licensed for router use;
  the account may be rate-limited or banned. Surfaced prominently in the UI.

``base_url`` is always the API *root* (SecForge appends ``/chat/completions`` or ``/messages``).
A ``{placeholder}`` in a base URL means the user must fill in a value (e.g. an Azure resource).

Two network helpers, both best-effort and credential-free on SecForge's side:

* ``probe_models`` — lists what an endpoint exposes (``GET <base>/models``) for the dropdown.
* ``check_endpoint`` — a one-token probe so the UI can show a works / valid-but-limited / failed
  signal. It classifies the HTTP outcome (see ``_classify``) so a rate-limited or wrong-model key
  reads as "key accepted, but…" rather than a rejected credential.

Nothing here installs or downloads anything.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Category ids the UI groups by. Labels + display order are localized on the frontend.
CATEGORIES: tuple[str, ...] = ("oauth", "free", "apikey", "local", "custom")


def _p(
    id: str,
    label: str,
    category: str,
    *,
    base_url: str = "",
    default_model: str = "",
    models: list[str] | None = None,
    tier: str = "standard",
    auth: str = "key",
    private: bool = False,
    api_style: str = "openai",
    flow: str = "",
    risk: bool = False,
    docs: str = "",
    note: str = "",
) -> dict[str, Any]:
    """Build one catalog entry with sane defaults so the table below stays readable.

    ``models`` is a short list of suggested model ids the UI offers as autocomplete (the way a
    full router hints a starting model per provider); the user can still type any id. When
    ``default_model`` is omitted it falls back to the first suggestion.
    """
    suggestions = models or []
    return {
        "id": id,
        "label": label,
        "category": category,
        "base_url": base_url,
        "default_model": default_model or (suggestions[0] if suggestions else ""),
        "models": suggestions,
        "tier": tier,
        "auth": auth,
        "private": private,
        "api_style": api_style,
        "flow": flow,
        "risk": risk,
        "docs": docs,
        "note": note,
    }


# ``note``/``docs`` are developer-facing; the UI shows a localized hint (i18n contract).
# Base URLs, api styles, and OAuth client ids are sourced from the 9Router registry so they
# match a working router rather than being guessed.
PROVIDER_TYPES: list[dict[str, Any]] = [
    # ── OAuth sign-in (device-code / browser PKCE) ────────────────────────────
    # These use a subscription/session; SecForge runs the flow and stores the token.
    _p("claude-code", "Claude Code", "oauth", base_url="https://api.anthropic.com/v1",
       default_model="claude-sonnet-4-6", tier="subscription", auth="oauth", flow="pkce",
       api_style="anthropic", risk=True, docs="https://claude.ai",
       models=["claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-sonnet-4-6",
               "claude-haiku-4-5-20251001"],
       note="Anthropic subscription via the Claude Code OAuth session."),
    _p("codex", "OpenAI Codex", "oauth", base_url="https://chatgpt.com/backend-api/codex",
       default_model="gpt-5.3-codex", tier="subscription", auth="oauth", flow="pkce",
       api_style="openai-responses", risk=True, docs="https://chatgpt.com/codex",
       models=["gpt-5.3-codex", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-high",
               "gpt-5.3-codex-low"],
       note="ChatGPT subscription via the Codex CLI OAuth session (Responses API)."),
    _p("github-copilot", "GitHub Copilot", "oauth", base_url="https://api.githubcopilot.com",
       default_model="gpt-4.1", tier="subscription", auth="oauth", flow="device",
       risk=True, docs="https://github.com/features/copilot",
       models=["gpt-4.1", "gpt-5.4", "gpt-5.4-mini", "claude-sonnet-4.6", "claude-opus-4.6",
               "gemini-2.5-pro"],
       note="GitHub device-code sign-in, then a Copilot token exchange. Fully wired."),
    _p("cursor", "Cursor IDE", "oauth", base_url="https://api2.cursor.sh",
       default_model="default", tier="subscription", auth="oauth", flow="pkce",
       api_style="cursor", risk=True, docs="https://cursor.com",
       models=["default", "claude-4.5-sonnet", "claude-4.5-opus", "claude-4.5-haiku",
               "gpt-5.2-codex"],
       note="Cursor uses a proprietary protobuf API — sign-in works; not drivable by the "
       "OpenAI agent loop yet."),
    _p("kilo-code", "Kilo Code", "oauth", base_url="https://api.kilo.ai/api/openrouter",
       default_model="anthropic/claude-sonnet-4-20250514", tier="subscription", auth="oauth",
       flow="device", docs="https://kilocode.ai",
       models=["anthropic/claude-sonnet-4-20250514", "anthropic/claude-opus-4-20250514",
               "google/gemini-2.5-pro", "openai/gpt-4.1", "deepseek/deepseek-chat"],
       note="Device-code sign-in; proxies the OpenRouter catalogue in OpenAI shape."),
    _p("cline", "Cline", "oauth", base_url="https://api.cline.bot/api/v1",
       default_model="anthropic/claude-sonnet-4.6", tier="subscription", auth="oauth",
       flow="pkce", docs="https://cline.bot",
       models=["anthropic/claude-sonnet-4.6", "anthropic/claude-opus-4.7", "openai/gpt-5.4",
               "google/gemini-3.1-pro-preview"],
       note="Browser PKCE sign-in; OpenAI-shaped chat endpoint."),
    _p("qwen-code", "Qwen Code", "oauth", base_url="https://portal.qwen.ai/v1",
       default_model="qwen3-coder-plus", tier="free", auth="oauth", flow="device",
       models=["qwen3-coder-plus", "qwen3-coder-flash", "coder-model", "vision-model"],
       docs="https://chat.qwen.ai", note="Qwen device-code sign-in (OpenAI shape)."),
    # NOTE: gemini-cli and kiro sign in via OAuth device/PKCE flows too, but they grant access
    # to a genuinely free consumer quota (Google/AWS), not a paid subscription — mirroring
    # 9Router's own registry (open-sse/providers/registry/{gemini-cli,kiro}.js are both
    # `category: "free"`), they live in the Free tier section below, not here, so this list
    # stays exactly "sign in with a subscription you already pay for."

    # ── Free tier / keyless hosted ────────────────────────────────────────────
    _p("openrouter", "OpenRouter", "free", base_url="https://openrouter.ai/api/v1",
       default_model="openai/gpt-4o-mini", tier="free", docs="https://openrouter.ai/keys",
       models=["openai/gpt-4o-mini", "anthropic/claude-3.5-sonnet",
               "google/gemini-2.0-flash-exp:free", "meta-llama/llama-3.3-70b-instruct",
               "deepseek/deepseek-chat"],
       note="One key, 400+ models — great for fallback variety in the pool."),
    _p("nvidia-nim", "NVIDIA NIM", "free", base_url="https://integrate.api.nvidia.com/v1",
       default_model="meta/llama-3.3-70b-instruct", tier="free",
       docs="https://build.nvidia.com",
       models=["meta/llama-3.3-70b-instruct", "deepseek-ai/deepseek-r1",
               "qwen/qwen2.5-coder-32b-instruct"],
       note="Free NIM inference endpoints."),
    _p("gemini", "Gemini", "free",
       base_url="https://generativelanguage.googleapis.com/v1beta/openai",
       default_model="gemini-2.5-flash", tier="free",
       docs="https://aistudio.google.com/apikey",
       models=["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash",
               "gemini-2.5-pro"],
       note="Google Gemini via its OpenAI-compatible endpoint. As of testing, only "
       "gemini-2.5-flash and gemini-2.5-flash-lite reliably have free-tier quota — "
       "gemini-2.0-flash and gemini-2.5-pro often return 429 (limit: 0) on new API keys."),
    _p("ollama-cloud", "Ollama Cloud", "free", base_url="https://ollama.com/v1",
       tier="free", docs="https://ollama.com",
       models=["gpt-oss:120b", "qwen3:235b", "deepseek-v3.1", "kimi-k2"],
       note="Hosted Ollama models via an API key."),
    _p("cloudflare", "Cloudflare Workers AI", "free",
       base_url="https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
       default_model="@cf/meta/llama-3.3-70b-instruct-fp8-fast", tier="free",
       docs="https://developers.cloudflare.com/workers-ai",
       models=["@cf/meta/llama-3.3-70b-instruct-fp8-fast", "@cf/meta/llama-3.1-8b-instruct",
               "@cf/mistralai/mistral-small-3.1-24b-instruct"],
       note="Replace {account_id}. OpenAI-compatible Workers AI gateway."),
    _p("byteplus", "BytePlus ModelArk", "free",
       base_url="https://ark.ap-southeast.bytepluses.com/api/v3",
       tier="free", docs="https://www.byteplus.com/en/product/modelark",
       note="BytePlus ModelArk — model id is an endpoint id you create in its console."),
    _p("vertex-ai", "Vertex AI", "free",
       base_url="https://{region}-aiplatform.googleapis.com",
       tier="free", docs="https://cloud.google.com/vertex-ai",
       models=["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
       note="Google Vertex AI — fill in {region}; needs a GCP bearer token."),
    _p("opencode", "OpenCode Free", "free", base_url="https://opencode.ai/zen/v1",
       default_model="claude-haiku-4-5", tier="free", auth="none", docs="https://opencode.ai",
       models=["claude-haiku-4-5", "claude-sonnet-4-6", "gemini-3-flash", "gpt-5.4",
               "gpt-5.4-mini"],
       note="Keyless OpenCode Zen endpoint (mirrors 9Router's opencode.js). Anonymous access "
       "has been flaky in testing — add OpenRouter too as a reliable fallback."),
    _p("gemini-cli", "Gemini CLI", "free",
       base_url="https://cloudcode-pa.googleapis.com/v1internal",
       default_model="gemini-2.5-pro", tier="free", auth="oauth", flow="pkce",
       api_style="gemini-cli", docs="https://github.com/google-gemini/gemini-cli",
       models=["gemini-2.5-pro", "gemini-2.5-flash", "gemini-3-pro-preview",
               "gemini-3-flash-preview"],
       note="Google OAuth (Code Assist) — a free consumer quota, not a paid subscription. "
       "Drivable via the internal generateContent shape."),
    _p("kiro", "Kiro AI", "free", base_url="https://runtime.us-east-1.kiro.dev",
       tier="free", auth="oauth", flow="device",
       api_style="kiro", docs="https://kiro.dev",
       models=["claude-sonnet-4.5", "claude-haiku-4.5", "deepseek-3.2"],
       note="AWS SSO OIDC device sign-in — a free AWS quota, not a paid subscription. "
       "Fully wired: chat runs over CodeWhisperer's GenerateAssistantResponse."),

    # ── API key providers (bring your own key) ────────────────────────────────
    _p("openai", "OpenAI", "apikey", base_url="https://api.openai.com/v1",
       default_model="gpt-4o-mini", docs="https://platform.openai.com/api-keys",
       models=["gpt-4o-mini", "gpt-4o", "gpt-4.1", "gpt-4.1-mini", "o3", "o4-mini"],
       note="Official OpenAI API. Use an sk-… key."),
    _p("anthropic", "Anthropic", "apikey", base_url="https://api.anthropic.com/v1",
       default_model="claude-sonnet-4-6", api_style="anthropic",
       docs="https://console.anthropic.com/settings/keys",
       models=["claude-sonnet-4-6", "claude-opus-4-8", "claude-opus-4-6",
               "claude-haiku-4-5-20251001", "claude-3-5-sonnet-20241022"],
       note="Claude via the native Messages API (x-api-key)."),

    # ── Local & private (no key; target data stays on your machine) ───────────
    _p("ollama", "Ollama", "local", base_url="http://localhost:11434/v1",
       default_model="llama3.2", tier="free", auth="none", private=True,
       models=["llama3.2", "llama3.1", "qwen2.5", "mistral", "phi3"],
       note="Local models via Ollama. No key; nothing leaves the machine."),
    _p("lmstudio", "LM Studio", "local", base_url="http://localhost:1234/v1",
       tier="free", auth="none", private=True,
       note="Local server from LM Studio. No key; the model id is whatever you loaded."),
    _p("9router", "9Router", "local", base_url="http://localhost:20128/v1",
       tier="free", auth="none", private=True,
       note="Local multi-account AI router; manage accounts in its own dashboard."),
    _p("antigravity", "Antigravity", "local", base_url="http://localhost:8045/v1",
       default_model="gemini-3-pro-high", tier="free", auth="none", private=True,
       models=["gemini-3-pro-high", "gemini-3.1-pro-preview", "gemini-3-flash",
               "gemini-2.5-flash", "gemini-2.0-flash", "claude-sonnet-4-6",
               "claude-opus-4-6-thinking", "gpt-oss-120b-medium"],
       note="Local Antigravity-Manager proxy (default port 8045). It serves OpenAI /v1, "
       "Claude /v1/messages and Gemini /v1beta from your managed accounts and holds the "
       "upstream credentials — change the port here if you configured a different one."),

    # ── Bring your own compatible endpoint (the escape hatch) ─────────────────
    _p("openai-compat", "Custom (OpenAI-compatible)", "custom", base_url="",
       api_style="openai",
       note="Any OpenAI-compatible /v1 URL — vLLM, LocalAI, a gateway, another vendor…"),
    _p("anthropic-compat", "Custom (Anthropic-compatible)", "custom", base_url="",
       api_style="anthropic",
       note="Any Anthropic-compatible /v1 URL that speaks the Messages API."),
]


# (url, json_payload, headers, timeout) -> (status_code, body). Injectable so tests need no network.
HttpPost = Callable[[str, dict[str, Any], dict[str, str], float], tuple[int, str]]


def probe_models(base_url: str, api_key: str = "", timeout: float = 5.0) -> list[str]:
    """List model ids from an OpenAI-compatible ``<base>/models`` endpoint (best effort)."""
    if not base_url:
        return []
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        req = Request(base_url.rstrip("/") + "/models", headers=headers, method="GET")
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - user-supplied endpoint
            data = json.loads(resp.read())
    except (HTTPError, URLError, OSError, json.JSONDecodeError):
        return []
    rows = data.get("data") if isinstance(data, dict) else data
    ids = [str(r["id"]) for r in rows or [] if isinstance(r, dict) and r.get("id")]
    return sorted(set(ids))


def _default_post(
    url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float
) -> tuple[int, str]:
    """POST JSON and return ``(status, body)``. A 4xx/5xx is a *result* (reachable), not a raise."""
    data = json.dumps(payload).encode()
    req = Request(url, data=data, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - user-supplied endpoint
            return resp.status, resp.read().decode("utf-8", "replace")
    except HTTPError as exc:  # endpoint answered, just unhappy (e.g. 401 bad key)
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - body is best-effort
            pass
        return exc.code, body


# Substrings that mark an auth failure even when the HTTP status isn't 401/403 — e.g. Google's
# OpenAI-compatible endpoint answers a *bad key* with 400 "Please pass a valid API key", not 401.
_AUTH_HINTS: tuple[str, ...] = (
    "api key", "api_key", "apikey", "unauthorized", "authentication", "invalid key",
    "invalid token", "invalid x-api-key", "no api key", "missing authorization",
    "missing authentication", "credential", "permission denied", "not authenticated",
)


def _classify(status: int, body: str) -> tuple[bool, str, str]:
    """Map an HTTP outcome to ``(ok, reason, error)``.

    A "Test" answers one question — is this credential usable? A non-2xx is *not* automatically a
    bad key: a valid key is routinely rate-limited (429), points at a model with no quota, or has a
    mistyped model id. Only 401/403 (or a body that says so) means the key was actually rejected.
    ``reason`` (set only when not ok) lets the UI show a hard auth failure (red) apart from a
    key-is-valid-but… state (amber), instead of flattening every non-2xx into "Failed":

      ``auth``         — key rejected: 401/403, or an auth-worded 4xx (Gemini's 400).
      ``rate_limited`` — 429: the key authenticated; it's just throttled / out of quota.
      ``reachable``    — other 4xx: the endpoint answered past auth (bad model id / unsupported
                         param), so the credential itself looks accepted.
      ``server``       — 5xx: a provider-side error, not a key problem.
      ``unreachable``  — no HTTP response (transport error / timeout; status 0).
    """
    if 200 <= status < 300:
        return True, "", ""
    err = (body or f"HTTP {status}")[:200]
    text = (body or "").lower()
    if status in (401, 403):
        return False, "auth", err
    if status == 429:
        return False, "rate_limited", err
    if 400 <= status < 500:
        # Some providers signal a bad key with 400 rather than 401 — trust the body wording.
        if any(hint in text for hint in _AUTH_HINTS):
            return False, "auth", err
        return False, "reachable", err
    if status >= 500:
        return False, "server", err
    return False, "unreachable", err


def _result(status: int, body: str) -> dict[str, Any]:
    """Build ``{ok, status[, reason, error]}``. A 2xx stays minimal: ``{ok, status}``."""
    ok, reason, err = _classify(status, body)
    result: dict[str, Any] = {"ok": ok, "status": status}
    if not ok:
        result["reason"] = reason
        result["error"] = err
    return result


def check_endpoint(
    base_url: str,
    api_key: str = "",
    model: str = "",
    *,
    api_style: str = "openai",
    http_post: HttpPost | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """One-token probe against ``base_url``. ``{ok, status, reason?, error?}`` — never raises.

    ``api_style`` selects the wire shape: OpenAI ``chat/completions`` (Bearer) or Anthropic
    ``messages`` (x-api-key + version header), so an Anthropic-only endpoint is tested honestly.
    A non-2xx is classified (see :func:`_classify`) so a valid-but-rate-limited or wrong-model key
    isn't reported as a rejected credential. The timeout is generous so a cold model's first token
    doesn't read as an unreachable endpoint.
    """
    if not base_url:
        return {"ok": False, "status": 0, "reason": "config", "error": "no base URL"}
    post = http_post or _default_post
    if api_style == "kiro":
        return _check_kiro(api_key, post, timeout)
    if api_style in ("gemini", "gemini-cli", "antigravity"):
        return _check_gemini(base_url, api_key, model, api_style, post, timeout)
    anthropic = api_style == "anthropic"
    suffix = "/messages" if anthropic else "/chat/completions"
    url = base_url.rstrip("/") + suffix
    headers = {"Content-Type": "application/json"}
    if anthropic:
        headers["anthropic-version"] = "2023-06-01"
        if api_key:
            headers["x-api-key"] = api_key
        payload: dict[str, Any] = {
            "model": model or "claude-sonnet-4-6",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "ping"}],
        }
    else:
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model": model or "gpt-4o-mini",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "ping"}],
        }
    try:
        status, body = post(url, payload, headers, timeout)
    except (URLError, OSError) as exc:  # connection refused, DNS, timeout — endpoint unreachable
        return {"ok": False, "status": 0, "reason": "unreachable",
                "error": str(getattr(exc, "reason", exc))}
    return _result(status, body)


def _probe(post: HttpPost, url: str, payload: dict[str, Any], headers: dict[str, str],
           timeout: float) -> dict[str, Any]:
    """Shared ``{ok, status, reason?, error?}`` POST probe used by the per-style checks below."""
    try:
        status, body = post(url, payload, headers, timeout)
    except (URLError, OSError) as exc:
        return {"ok": False, "status": 0, "reason": "unreachable",
                "error": str(getattr(exc, "reason", exc))}
    return _result(status, body)


def _check_kiro(api_key: str, post: HttpPost, timeout: float) -> dict[str, Any]:
    """Validate a Kiro token cheaply by listing CodeWhisperer profiles (no quota spend)."""
    if not api_key:
        return {"ok": False, "status": 0, "reason": "auth", "error": "no token — sign in first"}
    headers = {
        "Content-Type": "application/x-amz-json-1.0",
        "x-amz-target": "AmazonCodeWhispererService.ListAvailableProfiles",
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    url = "https://codewhisperer.us-east-1.amazonaws.com"
    return _probe(post, url, {"maxResults": 1}, headers, timeout)


def _check_gemini(base_url: str, api_key: str, model: str, api_style: str,
                  post: HttpPost, timeout: float) -> dict[str, Any]:
    """One-token ``generateContent`` ping for the Gemini family."""
    if not api_key:
        return {"ok": False, "status": 0, "reason": "auth", "error": "no token — sign in first"}
    base = base_url.rstrip("/")
    request = {
        "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
        "generationConfig": {"maxOutputTokens": 1},
    }
    if api_style == "gemini":
        url = f"{base}/models/{model or 'gemini-2.5-flash'}:generateContent"
        headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}
        payload: dict[str, Any] = request
    else:  # gemini-cli / antigravity — bearer + wrapped body
        url = f"{base}:generateContent"
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        payload = {"model": model or "gemini-2.5-flash", "request": request}
        if api_style == "antigravity":
            headers["x-request-source"] = "local"
            payload["requestType"] = "agent"
    return _probe(post, url, payload, headers, timeout)
