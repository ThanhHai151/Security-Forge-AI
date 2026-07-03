"""RouterBackend — one Backend that rotates over many accounts with quota/ban-aware fallback.

This is the native equivalent of an external multi-provider proxy: for each model call it
walks the eligible accounts (ordered by the store's rotation policy), tries one, and on a
rate-limit/auth/ban response (429/401/403) puts that account on a timed cooldown and falls
through to the next. Per-account health is kept in a process-wide table so a banned key stays
parked across runs and the Router page can show it. Each attempt uses the wire adapter matching
the account's ``api_style`` (:class:`OpenAICompatBackend` or :class:`AnthropicCompatBackend`),
pinned to that account's key+model; OAuth accounts have their token refreshed in place first.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from ai_framework.agent.contracts import RunConfig, Turn
from ai_framework.models.anthropic_compat import AnthropicCompatBackend
from ai_framework.models.base import ActResponse
from ai_framework.models.openai_compat import HttpError, OpenAICompatBackend, TransportError
from ai_framework.router.accounts import TIERS, Account, AccountStore
from ai_framework.router.oauth import OAuthError, OAuthManager
from ai_framework.router.usage import UsageStore

# Refresh an OAuth token this many seconds before it actually expires.
# 10 minutes: Kiro/AWS SSO tokens are often revoked upstream before the stated
# expiry, so a generous lead prevents the "valid locally, 400 upstream" failure.
_REFRESH_LEAD = 600.0

# Cooldown seconds per failure class. Auth/forbidden (likely a banned or wrong key) parks the
# account far longer than a transient rate-limit. 400 gets a short cooldown because it often
# means a stale OAuth token that will be refreshed on the next attempt.
_COOLDOWN = {429: 60, 400: 15, 401: 600, 403: 600}
_DEFAULT_COOLDOWN = 20

# Process-wide health table, keyed by account id. Shared across runs and read by the API.
_HEALTH: dict[str, dict[str, Any]] = {}
_HEALTH_LOCK = threading.Lock()


def _now() -> float:
    return time.time()


def _record(account_id: str, *, ok: bool, status: int, error: str = "", cooldown: int = 0) -> None:
    with _HEALTH_LOCK:
        h = _HEALTH.setdefault(
            account_id,
            {"calls": 0, "ok": 0, "fail": 0, "last_status": 0, "last_error": "",
             "cooldown_until": 0.0},
        )
        h["calls"] += 1
        h["last_status"] = status
        if ok:
            h["ok"] += 1
            h["last_error"] = ""
            h["cooldown_until"] = 0.0
        else:
            h["fail"] += 1
            h["last_error"] = error[:300]
            if cooldown:
                h["cooldown_until"] = _now() + cooldown


def health_snapshot() -> dict[str, dict[str, Any]]:
    """Copy of the health table with a derived ``cooling`` flag, for the status endpoint."""
    now = _now()
    with _HEALTH_LOCK:
        return {
            aid: {**h, "cooling": h.get("cooldown_until", 0) > now}
            for aid, h in _HEALTH.items()
        }


def _cooldown_for(status: int) -> int:
    return _COOLDOWN.get(status, _DEFAULT_COOLDOWN)


class RouterBackend:
    name = "router"

    def __init__(
        self,
        store: AccountStore,
        http_post: Any | None = None,
        oauth: OAuthManager | None = None,
        usage: UsageStore | None = None,
    ) -> None:
        self._store = store
        self._http_post = http_post  # injectable for tests
        self._oauth = oauth or OAuthManager()
        # Persistent per-account usage (calls + tokens) behind the Quota Tracker. Falls back to a
        # default-path store so a RouterBackend built without one still writes ai_usage.json.
        self._usage = usage or UsageStore()

    def _fresh_key(self, acct: Account) -> str:
        """Refresh an OAuth account's access token in place if it is at/near expiry."""
        if not acct.oauth_provider or not acct.refresh_token:
            return acct.api_key
        if acct.token_expiry and _now() < acct.token_expiry - _REFRESH_LEAD:
            return acct.api_key
        try:
            tokens = self._oauth.refresh(
                acct.oauth_provider, acct.refresh_token, acct.provider_data
            )
        except OAuthError:
            return acct.api_key  # let the upstream 401 drive the normal cooldown path
        self._store.update(acct.id, tokens)
        return tokens.get("api_key", acct.api_key)

    def _backend_for(self, acct: Account, key: str) -> Any:
        """Pick the wire adapter matching the account's ``api_style``.

        The bespoke adapters (Kiro/Antigravity/Gemini) are imported lazily so this module — and
        anything that only rotates OpenAI/Anthropic accounts — never pays to import the AWS
        EventStream parser or the Google cloaking layer.
        """
        style = acct.api_style
        if style == "anthropic":
            return AnthropicCompatBackend(
                base_url=acct.base_url,
                model=acct.model or "claude-sonnet-4-6",
                api_key=key or None,
                name=acct.id,
                http_post=self._http_post,
                extra_headers=acct.extra_headers or None,
                oauth=bool(acct.oauth_provider),
            )
        if style == "kiro":
            from ai_framework.models.kiro_backend import KiroBackend

            # Kiro speaks AWS CodeWhisperer's binary EventStream, not JSON — it uses its own
            # raw-bytes transport, so the router's JSON poster is intentionally not passed here.
            return KiroBackend(
                base_url=acct.base_url,
                model=acct.model or "claude-sonnet-4.5",
                api_key=key or None,
                name=acct.id,
                extra_headers=acct.extra_headers or None,
                provider_data=acct.provider_data,
            )
        if style == "antigravity":
            from ai_framework.models.antigravity_backend import AntigravityBackend

            return AntigravityBackend(
                base_url=acct.base_url,
                model=acct.model or "gemini-3-flash-agent",
                api_key=key or None,
                name=acct.id,
                http_post=self._http_post,
                extra_headers=acct.extra_headers or None,
                provider_data=acct.provider_data,
            )
        if style in ("gemini", "gemini-cli"):
            from ai_framework.models.gemini_backend import GeminiBackend

            return GeminiBackend(
                base_url=acct.base_url,
                model=acct.model or "gemini-2.5-flash",
                api_key=key or None,
                name=acct.id,
                http_post=self._http_post,
                extra_headers=acct.extra_headers or None,
                cli_style=(style == "gemini-cli"),
                provider_data=acct.provider_data,
            )
        return OpenAICompatBackend(
            base_url=acct.base_url,
            model=acct.model or "gpt-4o-mini",
            api_key=key or None,
            name=acct.id,
            http_post=self._http_post,
            extra_headers=acct.extra_headers or None,
        )

    def _candidates(self):
        accounts = [a for a in self._store.list_accounts() if a.enabled]
        now = _now()
        with _HEALTH_LOCK:
            live = [a for a in accounts if _HEALTH.get(a.id, {}).get("cooldown_until", 0) <= now]
        # If everything is cooling down, still try them all (better a long-shot than nothing).
        pool = live or accounts
        if self._store.get_policy() == "tiered":
            rank = {t: i for i, t in enumerate(TIERS)}
            pool = sorted(pool, key=lambda a: rank.get(a.tier, 1))
        return pool

    def _run(self, invoke: Callable[[OpenAICompatBackend], Any]) -> Any:
        candidates = self._candidates()
        if not candidates:
            raise RuntimeError(
                "no AI accounts configured — add one on the Router page "
                "(or run the offline backend)"
            )
        errors: list[str] = []
        for acct in candidates:
            key = self._fresh_key(acct)
            backend = self._backend_for(acct, key)
            try:
                result = invoke(backend)
                _record(acct.id, ok=True, status=200)
                usage = getattr(backend, "last_usage", None) or {}
                self._usage.record(
                    acct.id, ok=True,
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                )
                return result
            except HttpError as exc:
                # OAuth accounts: 400/401 often means the access token was revoked
                # upstream before its stated expiry. Force an immediate refresh and
                # retry once before cooling the account down.
                if exc.status in (400, 401) and acct.oauth_provider and acct.refresh_token:
                    try:
                        tokens = self._oauth.refresh(
                            acct.oauth_provider, acct.refresh_token, acct.provider_data
                        )
                        self._store.update(acct.id, tokens)
                        new_key = tokens.get("api_key", acct.api_key)
                        retry_backend = self._backend_for(acct, new_key)
                        result = invoke(retry_backend)
                        _record(acct.id, ok=True, status=200)
                        retry_usage = getattr(retry_backend, "last_usage", None) or {}
                        self._usage.record(
                            acct.id, ok=True,
                            prompt_tokens=retry_usage.get("prompt_tokens", 0),
                            completion_tokens=retry_usage.get("completion_tokens", 0),
                            total_tokens=retry_usage.get("total_tokens", 0),
                        )
                        return result
                    except Exception:  # noqa: BLE001 - refresh failure → fall through to cooldown
                        pass
                _record(
                    acct.id, ok=False, status=exc.status, error=str(exc),
                    cooldown=_cooldown_for(exc.status),
                )
                self._usage.record(acct.id, ok=False)
                errors.append(f"{acct.label}: HTTP {exc.status}")
            except TransportError as exc:
                _record(acct.id, ok=False, status=0, error=str(exc), cooldown=_DEFAULT_COOLDOWN)
                self._usage.record(acct.id, ok=False)
                errors.append(f"{acct.label}: {exc}")
            except Exception as exc:  # noqa: BLE001 - a bad account must not kill the run
                _record(acct.id, ok=False, status=-1, error=str(exc), cooldown=_DEFAULT_COOLDOWN)
                self._usage.record(acct.id, ok=False)
                errors.append(f"{acct.label}: {type(exc).__name__}")
        raise RuntimeError("all AI accounts failed — " + "; ".join(errors))

    def act(
        self, system: str, transcript: list[Turn], config: RunConfig, tools: list[dict[str, Any]]
    ) -> ActResponse:
        return self._run(lambda be: be.act(system, transcript, config, tools))

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        return self._run(lambda be: be.plan(system, transcript, config))
