"""Verbatim raw-output log — the external coding agent's own text, never edited or summarized.

Mirrors ``ai_framework.notes.store.JsonlFindingStore``'s shape: append-only JSON-lines, one
row per ingested paste. This is the durable "original context" the user asked to preserve —
``ai_framework.supervisor.ingest`` reads from this text to extract structured signals, but
never writes back into it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from ai_framework.security.redaction import redact_data


def _now() -> datetime:
    return datetime.now(UTC)


class RawLogEntry(BaseModel):
    domain: str
    text: str
    created_at: datetime = Field(default_factory=_now)


class RawLogStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, domain: str, text: str) -> RawLogEntry:
        entry = RawLogEntry(domain=domain, text=text)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(redact_data(entry.model_dump(mode="json"))) + "\n")
        return entry

    def for_domain(self, domain: str) -> list[RawLogEntry]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            entries = [RawLogEntry.model_validate_json(line) for line in fh if line.strip()]
        return [e for e in entries if e.domain == domain]
