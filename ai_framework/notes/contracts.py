"""Data contracts for structured findings — the human-facing output of a run.

A ``Finding`` is what ends up in the report you read afterwards: a titled observation with a
severity, the evidence that backs it, and (optionally) a link to the knowledge-base note that
explains the class. This is distinct from ``memory`` (the agent's internal working state):
findings are curated, exportable, and ordered by severity, per ``ai_framework/notes/README.md``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum
from uuid import uuid4

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(UTC)


class Severity(IntEnum):
    """Ordered so findings sort worst-first with plain ``sorted(..., reverse=True)``."""

    info = 0
    low = 1
    medium = 2
    high = 3
    critical = 4

    @classmethod
    def parse(cls, value: object) -> Severity:
        """Coerce a string/int (e.g. from a tool call) to a Severity; default ``info``."""
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value) if value in {s.value for s in cls} else cls.info
        try:
            return cls[str(value).strip().lower()]
        except KeyError:
            return cls.info


class Finding(BaseModel):
    """One structured, reviewable result captured during a run."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    run_id: str = ""
    target: str = ""
    step: int = 0
    title: str
    detail: str = ""
    severity: Severity = Severity.info
    evidence: str = ""
    kb_ref: str = ""
    tags: list[str] = Field(default_factory=list)
    # Adversarial verification: a finding is only trustworthy once its repro has been replayed
    # and confirmed. ``verified`` stays False until a verifier reproduces it; ``verification``
    # holds the human-readable outcome (what was replayed and what came back).
    verified: bool = False
    verification: str = ""
    created_at: datetime = Field(default_factory=_now)
