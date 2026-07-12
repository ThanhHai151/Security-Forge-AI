"""Deterministic secret redaction before transcripts or evidence cross a trust boundary."""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "cookie",
    "password",
    "passwd",
    "refresh_token",
    "secret",
    "set_cookie",
    "token",
}
_PATTERNS = (
    re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(r"(?i)\b((?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"(?i)\b(cookie|set-cookie)(\s*:\s*)[^\r\n]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b"),
)


def _key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def redact_text(value: str) -> str:
    """Redact common credential forms while leaving ordinary assessment text intact."""
    text = value
    text = _PATTERNS[0].sub(lambda m: m.group(1) + _REDACTED, text)
    text = _PATTERNS[1].sub(lambda m: m.group(1) + _REDACTED, text)
    text = _PATTERNS[2].sub(lambda m: m.group(1) + m.group(2) + _REDACTED, text)
    return _PATTERNS[3].sub(_REDACTED, text)


def redact_data(value: Any, *, parent_key: str = "") -> Any:
    """Recursively redact secret-bearing keys and credential-like strings."""
    if _key(parent_key) in _SENSITIVE_KEYS:
        if value in (None, "", [], {}):
            return value
        return _REDACTED
    if isinstance(value, dict):
        return {str(k): redact_data(v, parent_key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_data(item, parent_key=parent_key) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item, parent_key=parent_key) for item in value)
    if isinstance(value, set):
        return {redact_data(item, parent_key=parent_key) for item in value}
    if isinstance(value, str):
        return redact_text(value)
    return value
