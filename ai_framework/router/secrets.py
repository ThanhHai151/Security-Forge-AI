"""Small encrypted-at-rest vault used by the local provider account store.

Production deployments should set ``SECFORGE_MASTER_KEY`` from their secret manager. Local
single-user installs get a randomly generated mode-0600 key beside the account database. The
account JSON never contains plaintext API keys, refresh tokens, or provider-specific secrets.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

_PREFIX = "enc:v1:"
_SECRET_FIELDS = {"api_key", "refresh_token", "provider_data"}


class SecretDecryptionError(RuntimeError):
    """The configured master key cannot decrypt an existing account secret."""


def _secure_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


class SecretCipher:
    def __init__(self, account_path: str | Path) -> None:
        account_path = Path(account_path)
        configured = os.getenv("SECFORGE_MASTER_KEY_FILE", "").strip()
        self.key_path = Path(configured) if configured else account_path.with_suffix(".key")
        self._fernet: Fernet | None = None

    def _engine(self) -> Fernet:
        if self._fernet is not None:
            return self._fernet
        env_key = os.getenv("SECFORGE_MASTER_KEY", "").strip()
        if env_key:
            key = env_key.encode("ascii")
        elif self.key_path.exists():
            key = self.key_path.read_bytes().strip()
            os.chmod(self.key_path, 0o600)
        else:
            key = Fernet.generate_key()
            try:
                _secure_write(self.key_path, key + b"\n")
            except FileExistsError:
                key = self.key_path.read_bytes().strip()
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as exc:
            raise SecretDecryptionError("SECFORGE_MASTER_KEY is not a valid Fernet key") from exc
        return self._fernet

    def encrypt(self, value: Any) -> Any:
        if value in (None, "", {}):
            return value
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        return _PREFIX + self._engine().encrypt(raw).decode("ascii")

    def decrypt(self, value: Any) -> Any:
        if not isinstance(value, str) or not value.startswith(_PREFIX):
            return value
        try:
            raw = self._engine().decrypt(value.removeprefix(_PREFIX).encode("ascii"))
            return json.loads(raw)
        except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
            raise SecretDecryptionError(
                f"cannot decrypt provider credentials with key {self.key_path}"
            ) from exc

    def protect_store(self, data: dict[str, Any]) -> dict[str, Any]:
        protected = json.loads(json.dumps(data))
        for row in protected.get("accounts", []):
            if not isinstance(row, dict):
                continue
            for field in _SECRET_FIELDS:
                if field in row:
                    row[field] = self.encrypt(row[field])
        return protected

    @staticmethod
    def needs_migration(data: dict[str, Any]) -> bool:
        for row in data.get("accounts", []):
            if not isinstance(row, dict):
                continue
            for field in _SECRET_FIELDS:
                value = row.get(field)
                if value not in (None, "", {}) and not (
                    isinstance(value, str) and value.startswith(_PREFIX)
                ):
                    return True
        return False

    def unprotect_store(self, data: dict[str, Any]) -> dict[str, Any]:
        clear = json.loads(json.dumps(data))
        for row in clear.get("accounts", []):
            if not isinstance(row, dict):
                continue
            for field in _SECRET_FIELDS:
                if field in row:
                    row[field] = self.decrypt(row[field])
        return clear
