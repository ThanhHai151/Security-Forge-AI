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

from pydantic import BaseModel, Field, ValidationError

from ai_framework.router.secrets import SecretCipher

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
    # Optional daily quota ceilings the user sets in the Quota Tracker (0 = no limit). Advisory:
    # the tracker shows usage against them; the router does not hard-stop on them.
    quota_daily_requests: int = 0
    quota_daily_tokens: int = 0
    # OAuth bookkeeping — set only for accounts created via a sign-in flow. When ``oauth_provider``
    # is set and ``token_expiry`` has passed, the router refreshes ``api_key`` before use.
    oauth_provider: str = ""
    refresh_token: str = ""
    token_expiry: float = 0.0  # absolute epoch seconds; 0 => unknown / never expires
    # Free-form per-provider connection state that doesn't fit the fixed columns above, e.g.
    # Kiro's {authMethod, clientId, clientSecret, region, profileArn} or Antigravity's
    # {projectId, tierId}. Persisted verbatim; may hold a (shared, reverse-engineered) client
    # secret, so it is deliberately kept out of ``masked()``.
    provider_data: dict[str, str] = Field(default_factory=dict)

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
            # Non-secret hint so the UI can label how this account was connected.
            "auth_method": self.provider_data.get("authMethod", ""),
            # Advisory daily ceilings shown/edited in the Quota Tracker (0 = no limit).
            "quota_daily_requests": self.quota_daily_requests,
            "quota_daily_tokens": self.quota_daily_tokens,
        }


def default_path() -> str:
    return os.environ.get("SECFORGE_ACCOUNTS", "ai_accounts.json")


class AccountStore:
    """Thread-safe JSON-backed store of accounts + the rotation policy."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or default_path())
        self._lock = threading.Lock()
        self._cipher = SecretCipher(self.path)
        self._migrate_plaintext_store()

    def _migrate_plaintext_store(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if self._cipher.needs_migration(raw):
            self._save(self._cipher.unprotect_store(raw))

    # ── persistence ──
    def _load(self) -> dict:
        if not self.path.exists():
            return {"policy": "tiered", "accounts": []}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return self._cipher.unprotect_store(raw)
        except (json.JSONDecodeError, OSError):
            return {"policy": "tiered", "accounts": []}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename (same pattern as JsonRunStore.save) so a request landing mid-write —
        # e.g. the Providers page polling /accounts every 5s — never sees a torn/truncated file.
        tmp = self.path.with_suffix(".json.tmp")
        protected = self._cipher.protect_store(data)
        tmp.write_text(json.dumps(protected, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        os.chmod(self.path, 0o600)

    # ── accounts ──
    def list_accounts(self) -> list[Account]:
        """Every account that still validates against the current schema.

        A single incompatible or corrupted row must not take the whole pool down — skip it
        rather than raising, so one bad account doesn't 500 the entire Providers page.
        """
        accounts = []
        for row in self._load().get("accounts", []):
            try:
                accounts.append(Account.model_validate(row))
            except ValidationError:
                continue
        return accounts

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
