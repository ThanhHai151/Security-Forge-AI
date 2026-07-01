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

# Refresh an OAuth token this many seconds before it actually expires (clock skew + request time).
_REFRESH_LEAD = 120.0

# Cooldown seconds per failure class. Auth/forbidden (likely a banned or wrong key) parks the
# account far longer than a transient rate-limit.
_COOLDOWN = {429: 60, 401: 600, 403: 600}
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
    ) -> None:
        self._store = store
        self._http_post = http_post  # injectable for tests
        self._oauth = oauth or OAuthManager()

    def _fresh_key(self, acct: Account) -> str:
        """Refresh an OAuth account's access token in place if it is at/near expiry."""
        if not acct.oauth_provider or not acct.refresh_token:
            return acct.api_key
        if acct.token_expiry and _now() < acct.token_expiry - _REFRESH_LEAD:
            return acct.api_key
        try:
            tokens = self._oauth.refresh(acct.oauth_provider, acct.refresh_token)
        except OAuthError:
            return acct.api_key  # let the upstream 401 drive the normal cooldown path
        self._store.update(acct.id, tokens)
        return tokens.get("api_key", acct.api_key)

    def _backend_for(self, acct: Account, key: str) -> Any:
        """Pick the wire adapter matching the account's ``api_style``."""
        if acct.api_style == "anthropic":
            return AnthropicCompatBackend(
                base_url=acct.base_url,
                model=acct.model or "claude-sonnet-4-6",
                api_key=key or None,
                name=acct.id,
                http_post=self._http_post,
                extra_headers=acct.extra_headers or None,
                oauth=bool(acct.oauth_provider),
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
                return result
            except HttpError as exc:
                _record(
                    acct.id, ok=False, status=exc.status, error=str(exc),
                    cooldown=_cooldown_for(exc.status),
                )
                errors.append(f"{acct.label}: HTTP {exc.status}")
            except TransportError as exc:
                _record(acct.id, ok=False, status=0, error=str(exc), cooldown=_DEFAULT_COOLDOWN)
                errors.append(f"{acct.label}: {exc}")
            except Exception as exc:  # noqa: BLE001 - a bad account must not kill the run
                _record(acct.id, ok=False, status=-1, error=str(exc), cooldown=_DEFAULT_COOLDOWN)
                errors.append(f"{acct.label}: {type(exc).__name__}")
        raise RuntimeError("all AI accounts failed — " + "; ".join(errors))

    def act(
        self, system: str, transcript: list[Turn], config: RunConfig, tools: list[dict[str, Any]]
    ) -> ActResponse:
        return self._run(lambda be: be.act(system, transcript, config, tools))

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        return self._run(lambda be: be.plan(system, transcript, config))
