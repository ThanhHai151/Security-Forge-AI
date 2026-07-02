"""Persistent per-account usage — the data behind the Providers → Quota Tracker.

Where the in-memory health table (:mod:`ai_framework.router.router`) holds *live* cooldown state,
usage is persisted so lifetime totals and daily budgets survive restarts. The router records one
entry per model call (a request + its token counts); this store accumulates them per account into
a lifetime ``total`` plus one bucket per calendar day (UTC), trimmed to the last month.

Token counts are best-effort: the OpenAI and Anthropic wire shapes return a ``usage`` block, so
those calls carry real token numbers; backends that don't report usage record 0 tokens. *Calls*
are therefore always accurate even when *tokens* aren't available.

Stored as JSON at ``$SECFORGE_USAGE`` or ``ai_usage.json`` (gitignored). Same write-then-rename
persistence as :class:`~ai_framework.router.accounts.AccountStore` so a concurrent reader (the
Quota popup polls) never sees a torn file.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import threading
from pathlib import Path
from typing import Any

# Per-day buckets older than this are trimmed so the file can't grow without bound.
_RETAIN_DAYS = 30
# The counters every bucket (and the lifetime total) carry.
_FIELDS: tuple[str, ...] = (
    "calls", "ok", "fail", "prompt_tokens", "completion_tokens", "total_tokens",
)


def _today() -> str:
    return _dt.datetime.now(_dt.UTC).date().isoformat()


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def _zero() -> dict[str, int]:
    return dict.fromkeys(_FIELDS, 0)


def default_path() -> str:
    return os.environ.get("SECFORGE_USAGE", "ai_usage.json")


class UsageStore:
    """Thread-safe, JSON-backed per-account usage accumulator."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or default_path())
        self._lock = threading.Lock()

    # ── persistence ──
    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"accounts": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"accounts": {}}
        if not isinstance(data, dict) or not isinstance(data.get("accounts"), dict):
            return {"accounts": {}}
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # ── recording ──
    def record(
        self,
        account_id: str,
        *,
        ok: bool,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int = 0,
        day: str | None = None,
    ) -> None:
        """Add one call (and its tokens) to an account's lifetime total and today's bucket."""
        if not account_id:
            return
        prompt_tokens = max(0, int(prompt_tokens))
        completion_tokens = max(0, int(completion_tokens))
        total_tokens = max(0, int(total_tokens)) or (prompt_tokens + completion_tokens)
        day = day or _today()
        deltas = {
            "calls": 1,
            "ok": 1 if ok else 0,
            "fail": 0 if ok else 1,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        }
        with self._lock:
            data = self._load()
            accounts = data.setdefault("accounts", {})
            entry = accounts.setdefault(
                account_id, {"total": _zero(), "days": {}, "first_used": _now_iso()}
            )
            total = entry.setdefault("total", _zero())
            days = entry.setdefault("days", {})
            bucket = days.setdefault(day, _zero())
            for field, amount in deltas.items():
                total[field] = total.get(field, 0) + amount
                bucket[field] = bucket.get(field, 0) + amount
            entry["last_used"] = _now_iso()
            if len(days) > _RETAIN_DAYS:  # drop the oldest buckets, keep the newest _RETAIN_DAYS
                for old in sorted(days)[: len(days) - _RETAIN_DAYS]:
                    days.pop(old, None)
            self._save(data)

    # ── reading ──
    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Per-account view: ``{id: {total, today, days, first_used, last_used}}``."""
        today = _today()
        with self._lock:
            data = self._load()
        out: dict[str, dict[str, Any]] = {}
        for aid, entry in data.get("accounts", {}).items():
            days = entry.get("days", {}) or {}
            out[aid] = {
                "total": {**_zero(), **(entry.get("total") or {})},
                "today": {**_zero(), **(days.get(today) or {})},
                "days": days,
                "first_used": entry.get("first_used", ""),
                "last_used": entry.get("last_used", ""),
            }
        return out

    def reset(self, account_id: str | None = None) -> None:
        """Clear usage for one account, or the whole store when ``account_id`` is falsy."""
        with self._lock:
            data = self._load()
            if account_id:
                data.get("accounts", {}).pop(account_id, None)
            else:
                data["accounts"] = {}
            self._save(data)
