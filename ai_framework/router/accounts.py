"""Account store — the user's pool of AI resources, persisted to a JSON file.

Each account is one OpenAI-compatible endpoint (a key + base URL + default model) tagged with
a fallback ``tier``. This is the diverse-resource pool the router rotates over. Keys are stored
server-side only; the API layer masks them (``key_set`` + last-4 hint) and never returns them.

The file also holds the rotation ``policy`` so it survives restarts. Path defaults to
``$SECFORGE_ACCOUNTS`` or ``ai_accounts.json`` (gitignored).
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

# Fallback ordering for the "tiered" policy: paid subscriptions first (most reliable), then
# pay-as-you-go, then free pools (most likely to rate-limit).
TIERS = ("subscription", "standard", "free")
POLICIES = ("tiered", "round_robin")


class Account(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:8])
    label: str
    kind: str = "openai-compat"  # provider-type id (display/preset only)
    base_url: str
    api_key: str = ""
    model: str = ""
    tier: str = "standard"
    enabled: bool = True
    # Wire shape the router drives this account with: "openai" (/chat/completions) or
    # "anthropic" (/messages). Defaults keep every pre-existing account on the OpenAI path.
    api_style: str = "openai"
    # Static headers to replay upstream (e.g. GitHub Copilot's editor headers).
    extra_headers: dict[str, str] = Field(default_factory=dict)
    # OAuth bookkeeping — set only for accounts created via a sign-in flow. When ``oauth_provider``
    # is set and ``token_expiry`` has passed, the router refreshes ``api_key`` before use.
    oauth_provider: str = ""
    refresh_token: str = ""
    token_expiry: float = 0.0  # absolute epoch seconds; 0 => unknown / never expires

    def masked(self) -> dict:
        """Public view: never expose the raw key or refresh token."""
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "base_url": self.base_url,
            "model": self.model,
            "tier": self.tier,
            "enabled": self.enabled,
            "api_style": self.api_style,
            "oauth_provider": self.oauth_provider,
            "key_set": bool(self.api_key),
            "key_hint": (self.api_key[-4:] if self.api_key else ""),
        }


def default_path() -> str:
    return os.environ.get("SECFORGE_ACCOUNTS", "ai_accounts.json")


class AccountStore:
    """Thread-safe JSON-backed store of accounts + the rotation policy."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or default_path())
        self._lock = threading.Lock()

    # ── persistence ──
    def _load(self) -> dict:
        if not self.path.exists():
            return {"policy": "tiered", "accounts": []}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"policy": "tiered", "accounts": []}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # ── accounts ──
    def list_accounts(self) -> list[Account]:
        return [Account.model_validate(a) for a in self._load().get("accounts", [])]

    def add(self, account: Account) -> Account:
        with self._lock:
            data = self._load()
            data.setdefault("accounts", []).append(account.model_dump())
            self._save(data)
        return account

    def update(self, account_id: str, fields: dict) -> Account | None:
        with self._lock:
            data = self._load()
            for row in data.get("accounts", []):
                if row["id"] == account_id:
                    # Only overwrite the key when a non-empty one is supplied.
                    if "api_key" in fields and not fields["api_key"]:
                        fields.pop("api_key")
                    row.update({k: v for k, v in fields.items() if k != "id"})
                    self._save(data)
                    return Account.model_validate(row)
        return None

    def remove(self, account_id: str) -> bool:
        with self._lock:
            data = self._load()
            before = len(data.get("accounts", []))
            data["accounts"] = [a for a in data.get("accounts", []) if a["id"] != account_id]
            self._save(data)
            return len(data["accounts"]) < before

    def get(self, account_id: str) -> Account | None:
        return next((a for a in self.list_accounts() if a.id == account_id), None)

    # ── policy ──
    def get_policy(self) -> str:
        policy = self._load().get("policy", "tiered")
        return policy if policy in POLICIES else "tiered"

    def set_policy(self, policy: str) -> str:
        if policy not in POLICIES:
            raise ValueError(f"unknown policy: {policy}")
        with self._lock:
            data = self._load()
            data["policy"] = policy
            self._save(data)
        return policy
