"""Runtime enforcement of quantitative Rules of Engagement limits."""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from ai_framework.harness.contracts import RulesOfEngagement


class EngagementLimiter:
    """Thread-safe request pacing, concurrency, body-size, and login-attempt limits."""

    def __init__(self, roe: RulesOfEngagement) -> None:
        self.roe = roe
        self._semaphore = threading.BoundedSemaphore(roe.max_concurrency)
        self._lock = threading.Lock()
        self._next_request_at = 0.0
        self._auth_attempts: dict[str, int] = {}

    @staticmethod
    def _body_size(args: dict[str, Any]) -> int:
        bodies = [args.get("body"), args.get("data")]
        return max(
            (
                len(
                    value.encode("utf-8")
                    if isinstance(value, str)
                    else json.dumps(value, default=str).encode("utf-8")
                )
                for value in bodies
                if value not in (None, "")
            ),
            default=0,
        )

    @staticmethod
    def _account_key(args: dict[str, Any]) -> str:
        data = args.get("data") or {}
        if isinstance(data, dict):
            for name in ("username", "email", "user", "login", "account"):
                if data.get(name):
                    return str(data[name]).strip().lower()
        return str(args.get("url", "unknown-account"))

    def before(self, call: Any, tool: Any) -> bool:
        args = getattr(call, "arguments", {}) or {}
        size = self._body_size(args)
        if size > self.roe.max_request_body_bytes:
            raise PermissionError(
                f"request body is {size} bytes; RoE limit is {self.roe.max_request_body_bytes}"
            )

        if getattr(call, "name", "") == "login":
            account = self._account_key(args)
            with self._lock:
                attempts = self._auth_attempts.get(account, 0)
                if attempts >= self.roe.max_auth_attempts_per_account:
                    raise PermissionError(
                        f"authentication-attempt limit reached for account {account!r}"
                    )
                self._auth_attempts[account] = attempts + 1

        if not bool(getattr(tool, "touches_network", False)):
            return False

        self._semaphore.acquire()
        interval = 1.0 / self.roe.max_requests_per_second
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next_request_at)
            self._next_request_at = scheduled + interval
        delay = scheduled - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        return True

    def after(self, acquired: bool) -> None:
        if acquired:
            self._semaphore.release()
