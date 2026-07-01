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
* ``check_endpoint`` — a one-token probe so the UI can show a green/red "this works" signal.

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
    tier: str = "standard",
    auth: str = "key",
    private: bool = False,
    api_style: str = "openai",
    flow: str = "",
    risk: bool = False,
    docs: str = "",
    note: str = "",
) -> dict[str, Any]:
    """Build one catalog entry with sane defaults so the table below stays readable."""
    return {
        "id": id,
        "label": label,
        "category": category,
        "base_url": base_url,
        "default_model": default_model,
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
       note="Anthropic subscription via the Claude Code OAuth session."),
    _p("codex", "OpenAI Codex", "oauth", base_url="https://chatgpt.com/backend-api/codex",
       default_model="gpt-5.3-codex", tier="subscription", auth="oauth", flow="pkce",
       api_style="openai-responses", risk=True, docs="https://chatgpt.com/codex",
       note="ChatGPT subscription via the Codex CLI OAuth session (Responses API)."),
    _p("github-copilot", "GitHub Copilot", "oauth", base_url="https://api.githubcopilot.com",
       default_model="gpt-5.4", tier="subscription", auth="oauth", flow="device",
       risk=True, docs="https://github.com/features/copilot",
       note="GitHub device-code sign-in, then a Copilot token exchange. Fully wired."),
    _p("cursor", "Cursor IDE", "oauth", base_url="https://api2.cursor.sh",
       default_model="default", tier="subscription", auth="oauth", flow="pkce",
       api_style="cursor", risk=True, docs="https://cursor.com",
       note="Cursor uses a proprietary protobuf API — sign-in works; not drivable by the "
       "OpenAI agent loop yet."),
    _p("kilo-code", "Kilo Code", "oauth", base_url="https://api.kilo.ai/api/openrouter",
       default_model="anthropic/claude-sonnet-4-20250514", tier="subscription", auth="oauth",
       flow="device", docs="https://kilocode.ai",
       note="Device-code sign-in; proxies the OpenRouter catalogue in OpenAI shape."),
    _p("cline", "Cline", "oauth", base_url="https://api.cline.bot/api/v1",
       default_model="anthropic/claude-sonnet-4.6", tier="subscription", auth="oauth",
       flow="pkce", docs="https://cline.bot",
       note="Browser PKCE sign-in; OpenAI-shaped chat endpoint."),
    _p("qwen-code", "Qwen Code", "oauth", base_url="https://portal.qwen.ai/v1",
       default_model="qwen3-coder-plus", tier="free", auth="oauth", flow="device",
       docs="https://chat.qwen.ai", note="Qwen device-code sign-in (OpenAI shape)."),
    _p("gemini-cli", "Gemini CLI", "oauth",
       base_url="https://cloudcode-pa.googleapis.com/v1internal",
       default_model="gemini-2.5-pro", tier="free", auth="oauth", flow="pkce",
       api_style="gemini-cli", docs="https://github.com/google-gemini/gemini-cli",
       note="Google OAuth (Code Assist). Internal API shape — sign-in works; not yet drivable."),
    _p("kiro", "Kiro AI", "oauth", base_url="https://runtime.us-east-1.kiro.dev",
       default_model="", tier="free", auth="oauth", flow="device",
       api_style="kiro", docs="https://kiro.dev",
       note="AWS SSO OIDC device sign-in. Proprietary API shape — sign-in only for now."),

    # ── Free tier / keyless hosted ────────────────────────────────────────────
    _p("openrouter", "OpenRouter", "free", base_url="https://openrouter.ai/api/v1",
       default_model="openai/gpt-4o-mini", tier="free", docs="https://openrouter.ai/keys",
       note="One key, 400+ models — great for fallback variety in the pool."),
    _p("nvidia-nim", "NVIDIA NIM", "free", base_url="https://integrate.api.nvidia.com/v1",
       default_model="meta/llama-3.3-70b-instruct", tier="free",
       docs="https://build.nvidia.com", note="Free NIM inference endpoints."),
    _p("gemini", "Gemini", "free",
       base_url="https://generativelanguage.googleapis.com/v1beta/openai",
       default_model="gemini-2.0-flash", tier="free",
       docs="https://aistudio.google.com/apikey",
       note="Google Gemini via its OpenAI-compatible endpoint. Generous free tier."),
    _p("ollama-cloud", "Ollama Cloud", "free", base_url="https://ollama.com/v1",
       default_model="", tier="free", docs="https://ollama.com",
       note="Hosted Ollama models via an API key."),
    _p("cloudflare", "Cloudflare Workers AI", "free",
       base_url="https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
       default_model="@cf/meta/llama-3.3-70b-instruct-fp8-fast", tier="free",
       docs="https://developers.cloudflare.com/workers-ai",
       note="Replace {account_id}. OpenAI-compatible Workers AI gateway."),
    _p("byteplus", "BytePlus ModelArk", "free",
       base_url="https://ark.ap-southeast.bytepluses.com/api/v3",
       default_model="", tier="free", docs="https://www.byteplus.com/en/product/modelark",
       note="BytePlus ModelArk (international Volcengine)."),
    _p("vertex-ai", "Vertex AI", "free",
       base_url="https://{region}-aiplatform.googleapis.com", default_model="",
       tier="free", docs="https://cloud.google.com/vertex-ai",
       note="Google Vertex AI — fill in {region}; needs a GCP bearer token."),
    _p("opencode", "OpenCode Free", "free", base_url="https://opencode.ai/zen/free/v1",
       default_model="", tier="free", auth="none", docs="https://opencode.ai",
       note="Keyless free tier from OpenCode Zen."),

    # ── API key providers (bring your own key) ────────────────────────────────
    _p("openai", "OpenAI", "apikey", base_url="https://api.openai.com/v1",
       default_model="gpt-4o-mini", docs="https://platform.openai.com/api-keys",
       note="Official OpenAI API. Use an sk-… key."),
    _p("anthropic", "Anthropic", "apikey", base_url="https://api.anthropic.com/v1",
       default_model="claude-sonnet-4-6", api_style="anthropic",
       docs="https://console.anthropic.com/settings/keys",
       note="Claude via the native Messages API (x-api-key)."),
    _p("deepseek", "DeepSeek", "apikey", base_url="https://api.deepseek.com/v1",
       default_model="deepseek-chat", docs="https://platform.deepseek.com",
       note="Low-cost, strong reasoning models."),
    _p("groq", "Groq", "apikey", base_url="https://api.groq.com/openai/v1",
       default_model="llama-3.3-70b-versatile", tier="free", docs="https://console.groq.com/keys",
       note="Very fast inference, generous free tier."),
    _p("mistral", "Mistral", "apikey", base_url="https://api.mistral.ai/v1",
       default_model="mistral-large-latest", docs="https://console.mistral.ai/api-keys"),
    _p("xai", "xAI (Grok)", "apikey", base_url="https://api.x.ai/v1",
       default_model="grok-4", docs="https://console.x.ai", note="Grok models."),
    _p("cerebras", "Cerebras", "apikey", base_url="https://api.cerebras.ai/v1",
       default_model="llama-3.3-70b", tier="free", docs="https://cloud.cerebras.ai",
       note="Extremely fast wafer-scale inference."),
    _p("perplexity", "Perplexity", "apikey", base_url="https://api.perplexity.ai",
       default_model="sonar", docs="https://www.perplexity.ai/settings/api"),
    _p("together", "Together AI", "apikey", base_url="https://api.together.xyz/v1",
       default_model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
       docs="https://api.together.xyz/settings/api-keys"),
    _p("fireworks", "Fireworks AI", "apikey", base_url="https://api.fireworks.ai/inference/v1",
       default_model="accounts/fireworks/models/llama-v3p3-70b-instruct",
       docs="https://fireworks.ai/account/api-keys"),
    _p("hyperbolic", "Hyperbolic", "apikey", base_url="https://api.hyperbolic.xyz/v1",
       default_model="meta-llama/Llama-3.3-70B-Instruct", docs="https://app.hyperbolic.xyz"),
    _p("nebius", "Nebius AI", "apikey", base_url="https://api.studio.nebius.ai/v1",
       default_model="meta-llama/Llama-3.3-70B-Instruct", docs="https://studio.nebius.ai"),
    _p("siliconflow", "SiliconFlow", "apikey", base_url="https://api.siliconflow.com/v1",
       default_model="deepseek-ai/DeepSeek-V3", docs="https://siliconflow.com"),
    _p("chutes", "Chutes AI", "apikey", base_url="https://llm.chutes.ai/v1",
       default_model="", docs="https://chutes.ai"),
    _p("cohere", "Cohere", "apikey", base_url="https://api.cohere.ai/compatibility/v1",
       default_model="command-r-plus", docs="https://dashboard.cohere.com/api-keys",
       note="Cohere via its OpenAI-compatible endpoint."),
    _p("blackbox", "Blackbox AI", "apikey", base_url="https://api.blackbox.ai/v1",
       default_model="", docs="https://www.blackbox.ai"),
    _p("commandcode", "Command Code", "apikey", base_url="https://api.commandcode.ai/alpha",
       default_model="", docs="https://commandcode.ai",
       note="Non-standard generate API — may need the Custom card instead."),
    _p("kimi", "Kimi (Moonshot)", "apikey", base_url="https://api.moonshot.cn/v1",
       default_model="moonshot-v1-8k", docs="https://platform.moonshot.cn",
       note="Moonshot Kimi (OpenAI shape). Kimi Coding uses the Anthropic shape."),
    _p("glm-coding", "GLM Coding", "apikey", base_url="https://api.z.ai/api/anthropic/v1",
       default_model="glm-4.6", api_style="anthropic", docs="https://z.ai",
       note="Zhipu GLM coding plan via the Anthropic-compatible endpoint."),
    _p("glm-cn", "GLM (China)", "apikey", base_url="https://open.bigmodel.cn/api/paas/v4",
       default_model="glm-4-plus", docs="https://open.bigmodel.cn",
       note="Zhipu GLM (mainland) OpenAI-compatible endpoint."),
    _p("minimax", "Minimax", "apikey", base_url="https://api.minimax.io/anthropic/v1",
       default_model="MiniMax-M2", api_style="anthropic", docs="https://www.minimax.io",
       note="Minimax (international) via the Anthropic-compatible endpoint."),
    _p("minimax-cn", "Minimax (China)", "apikey",
       base_url="https://api.minimaxi.com/anthropic/v1", default_model="MiniMax-M2",
       api_style="anthropic", docs="https://www.minimaxi.com"),
    _p("alibaba", "Alibaba (Qwen)", "apikey",
       base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
       default_model="qwen-plus", docs="https://dashscope.console.aliyun.com",
       note="Alibaba DashScope (mainland) OpenAI-compatible mode."),
    _p("alibaba-intl", "Alibaba Intl", "apikey",
       base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
       default_model="qwen-plus", docs="https://dashscope-intl.console.aliyun.com"),
    _p("volcengine", "Volcengine Ark", "apikey",
       base_url="https://ark.cn-beijing.volces.com/api/v3", default_model="",
       docs="https://www.volcengine.com/product/ark",
       note="Volcengine Ark — model id is an endpoint id (ep-…)."),
    _p("xiaomi-mimo", "Xiaomi MiMo", "apikey", base_url="https://api.xiaomimimo.com/v1",
       default_model="", docs="https://xiaomimimo.com"),
    _p("xiaomi-tokenplan", "Xiaomi MiMo (Token Plan)", "apikey",
       base_url="https://token-plan-sgp.xiaomimimo.com/v1", default_model="",
       docs="https://xiaomimimo.com", note="Singapore region; other regions available."),
    _p("opencode-go", "OpenCode Go", "apikey", base_url="https://opencode.ai/zen/go/v1",
       default_model="", docs="https://opencode.ai"),
    _p("azure-openai", "Azure OpenAI", "apikey",
       base_url="https://{resource}.openai.azure.com/openai/v1", default_model="",
       docs="https://learn.microsoft.com/azure/ai-services/openai",
       note="Replace {resource}; Azure keys use the api-key header."),
    _p("vertex-partner", "Vertex Partner", "apikey",
       base_url="https://aiplatform.googleapis.com", default_model="",
       docs="https://cloud.google.com/vertex-ai",
       note="Vertex AI partner (MaaS) models — needs a GCP bearer token."),

    # ── Local & private (no key; target data stays on your machine) ───────────
    _p("ollama", "Ollama", "local", base_url="http://localhost:11434/v1",
       default_model="llama3.2", tier="free", auth="none", private=True,
       note="Local models via Ollama. No key; nothing leaves the machine."),
    _p("lmstudio", "LM Studio", "local", base_url="http://localhost:1234/v1",
       default_model="", tier="free", auth="none", private=True,
       note="Local server from LM Studio. No key."),
    _p("9router", "9Router", "local", base_url="http://localhost:20128/v1",
       default_model="", tier="free", auth="none", private=True,
       note="Local multi-account AI router; manage accounts in its own dashboard."),
    _p("antigravity", "Antigravity", "local", base_url="http://localhost:8045/v1",
       default_model="", tier="free", auth="none", private=True,
       note="Local Antigravity-Manager proxy; it holds the upstream credentials."),

    # ── Bring your own compatible endpoint (the escape hatch) ─────────────────
    _p("openai-compat", "Custom (OpenAI-compatible)", "custom", base_url="",
       default_model="", api_style="openai",
       note="Any OpenAI-compatible /v1 URL — vLLM, LocalAI, a gateway, another vendor…"),
    _p("anthropic-compat", "Custom (Anthropic-compatible)", "custom", base_url="",
       default_model="", api_style="anthropic",
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


def check_endpoint(
    base_url: str,
    api_key: str = "",
    model: str = "",
    *,
    api_style: str = "openai",
    http_post: HttpPost | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """One-token probe against ``base_url``. ``{ok, status, error?}`` — never raises.

    ``api_style`` selects the wire shape: OpenAI ``chat/completions`` (Bearer) or Anthropic
    ``messages`` (x-api-key + version header), so an Anthropic-only endpoint is tested honestly.
    """
    if not base_url:
        return {"ok": False, "status": 0, "error": "no base URL"}
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
    post = http_post or _default_post
    try:
        status, body = post(url, payload, headers, timeout)
    except (URLError, OSError) as exc:  # connection refused, DNS, timeout — endpoint unreachable
        return {"ok": False, "status": 0, "error": str(getattr(exc, "reason", exc))}
    ok = 200 <= status < 300
    result: dict[str, Any] = {"ok": ok, "status": status}
    if not ok:
        result["error"] = (body or f"HTTP {status}")[:200]
    return result
