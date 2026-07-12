"""Append-only, hash-chained record of tool decisions and results."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ai_framework.security.redaction import redact_data

_GENESIS = "0" * 64


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class EvidenceLedger:
    """A mode-0600 JSONL ledger whose records form a verifiable SHA-256 chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _rows(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def append(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            rows = self._rows()
            previous = rows[-1].get("record_hash", _GENESIS) if rows else _GENESIS
            record = {
                "sequence": len(rows) + 1,
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event,
                "previous_hash": previous,
                "payload": redact_data(payload),
            }
            record["record_hash"] = hashlib.sha256(_canonical(record)).hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, _canonical(record) + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(self.path, 0o600)
            return record

    def record_tool(self, call: Any, result: Any, ctx: Any) -> dict[str, Any]:
        roe = getattr(ctx, "rules_of_engagement", None)
        digest = ""
        if roe is not None:
            from ai_framework.harness.policy import scope_digest

            digest = scope_digest(roe)
        return self.append(
            "tool_result",
            {
                "run_id": getattr(ctx, "run_id", ""),
                "call_id": getattr(call, "id", ""),
                "tool": getattr(call, "name", ""),
                "arguments": getattr(call, "arguments", {}) or {},
                "target": getattr(ctx, "primary_target", ""),
                "scope_digest": digest,
                "ok": bool(getattr(result, "ok", False)),
                "result": getattr(result, "log", ""),
            },
        )

    def verify(self) -> tuple[bool, str]:
        previous = _GENESIS
        for expected_sequence, row in enumerate(self._rows(), 1):
            claimed = str(row.get("record_hash", ""))
            body = {k: v for k, v in row.items() if k != "record_hash"}
            actual = hashlib.sha256(_canonical(body)).hexdigest()
            if row.get("sequence") != expected_sequence:
                return False, f"sequence mismatch at record {expected_sequence}"
            if row.get("previous_hash") != previous:
                return False, f"chain mismatch at record {expected_sequence}"
            if not claimed or not hmac_compare(claimed, actual):
                return False, f"hash mismatch at record {expected_sequence}"
            previous = claimed
        count = expected_sequence if "expected_sequence" in locals() else 0
        return True, f"verified {count} records"


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)
