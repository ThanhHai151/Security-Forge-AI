"""Provider catalog for the Providers page — what runs the SecForge agent.

A "connection" here is the agent's fuel: one OpenAI-compatible ``base_url`` + key + model
(see :mod:`ai_framework.router.accounts`) that the Hermes loop, Defense review, and VI
translation all run on. This is *not* a generic LLM-aggregator list — it is curated to what a
pentester actually reaches for, plus a first-class **Custom** escape hatch that covers
everything else (vLLM, LocalAI, a gateway, another vendor's compatible endpoint, …).

Catalog axes (chosen for security work, not vendor billing):

* ``recommended`` — solid hosted defaults; bring an API key.
* ``local``       — runs on your own machine; ``private`` so target data never leaves the box.
* ``custom``      — any OpenAI-compatible URL you point at.

Alongside these connections the agent always has a keyless **Offline** mode (rule-based,
:mod:`ai_framework.models.offline`) — the frontend surfaces that separately; it needs no preset.

Two network helpers, both best-effort and credential-free on SecForge's side:

* ``probe_models`` — lists what an endpoint exposes (``GET <base>/models``) for the model dropdown.
* ``check_endpoint`` — a one-token ``chat/completions`` call so the UI can show a green/red
  "this actually works" signal. Both accept an injectable poster so tests need no network.

Nothing here installs or downloads anything.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Category ids the UI groups by, in display order. Labels are localized on the frontend.
CATEGORIES: tuple[str, ...] = ("recommended", "local", "custom")

# id, label, category, base_url, default_model, tier, auth ("key" | "none"), private, note.
# ``tier`` is the sensible default for the rotation policy; the user can change it per account.
# ``auth`` is a hint only — a local runtime may ignore keys, a custom endpoint may want one.
# ``private`` true means the model runs on-box, so target data never leaves the machine.
# ``note`` is developer-facing documentation; the UI shows a localized hint instead (i18n contract).
PROVIDER_TYPES: list[dict[str, Any]] = [
    # ── Recommended hosted defaults (bring a key) ─────────────────────────────
    {
        "id": "anthropic",
        "label": "Anthropic (Claude)",
        "category": "recommended",
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-sonnet-4-6",
        "tier": "subscription",
        "auth": "key",
        "private": False,
        "note": "Claude via Anthropic's OpenAI-compatible endpoint. The native backend "
        "(thinking/effort) is also available to the TUI/CLI.",
    },
    {
        "id": "openai",
        "label": "OpenAI",
        "category": "recommended",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "tier": "standard",
        "auth": "key",
        "private": False,
        "note": "Official OpenAI API. Use an sk-… key.",
    },
    {
        "id": "openrouter",
        "label": "OpenRouter",
        "category": "recommended",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "openai/gpt-4o-mini",
        "tier": "standard",
        "auth": "key",
        "private": False,
        "note": "One key, 400+ models — good for fallback variety in the pool.",
    },
    {
        "id": "deepseek",
        "label": "DeepSeek",
        "category": "recommended",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "tier": "standard",
        "auth": "key",
        "private": False,
        "note": "Low-cost, strong reasoning models.",
    },
    {
        "id": "groq",
        "label": "Groq",
        "category": "recommended",
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "tier": "free",
        "auth": "key",
        "private": False,
        "note": "Very fast inference, generous free tier — good for cheap iterations.",
    },
    # ── Local & private (no key; target data stays on your machine) ───────────
    {
        "id": "ollama",
        "label": "Ollama",
        "category": "local",
        "base_url": "http://localhost:11434/v1",
        "default_model": "llama3.2",
        "tier": "free",
        "auth": "none",
        "private": True,
        "note": "Local models via Ollama. No key; nothing leaves the machine.",
    },
    {
        "id": "lmstudio",
        "label": "LM Studio",
        "category": "local",
        "base_url": "http://localhost:1234/v1",
        "default_model": "",
        "tier": "free",
        "auth": "none",
        "private": True,
        "note": "Local server from LM Studio. No key.",
    },
    {
        "id": "9router",
        "label": "9Router",
        "category": "local",
        "base_url": "http://localhost:20128/v1",
        "default_model": "",
        "tier": "free",
        "auth": "none",
        "private": True,
        "note": "Local multi-account AI router; manage accounts in its own dashboard.",
    },
    {
        "id": "antigravity",
        "label": "Antigravity",
        "category": "local",
        "base_url": "http://localhost:8045/v1",
        "default_model": "",
        "tier": "free",
        "auth": "none",
        "private": True,
        "note": "Local Antigravity-Manager proxy; it holds the upstream credentials.",
    },
    # ── Bring your own compatible endpoint ────────────────────────────────────
    {
        "id": "openai-compat",
        "label": "Custom (OpenAI-compatible)",
        "category": "custom",
        "base_url": "",
        "default_model": "",
        "tier": "standard",
        "auth": "key",
        "private": False,
        "note": "Any OpenAI-compatible /v1 URL — vLLM, LocalAI, a gateway, another vendor…",
    },
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
    http_post: HttpPost | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """One-token ``chat/completions`` probe. ``{ok, status, error?}`` — never raises."""
    if not base_url:
        return {"ok": False, "status": 0, "error": "no base URL"}
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
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
