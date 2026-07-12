"""Data contracts for structured findings — the human-facing output of a run.

A ``Finding`` is what ends up in the report you read afterwards: a titled observation with a
severity, the evidence that backs it, and (optionally) a link to the knowledge-base note that
explains the class. This is distinct from ``memory`` (the agent's internal working state):
findings are curated, exportable, and ordered by severity, per ``ai_framework/notes/README.md``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
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


class FindingStatus(StrEnum):
    draft = "draft"
    reproduced = "reproduced"
    reviewed = "reviewed"
    accepted_risk = "accepted_risk"
    fixed = "fixed"
    retest_passed = "retest_passed"
    retest_failed = "retest_failed"


class Confidence(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"


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
    status: FindingStatus = FindingStatus.draft
    confidence: Confidence = Confidence.low
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str = ""
    cwe: list[str] = Field(default_factory=list)
    owasp: str = ""
    wstg: list[str] = Field(default_factory=list)
    attack: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    remediation_owner: str = ""
    reviewed_by: str = ""
    retest_note: str = ""
    # Adversarial verification: a finding is only trustworthy once its repro has been replayed
    # and confirmed. ``verified`` stays False until a verifier reproduces it; ``verification``
    # holds the human-readable outcome (what was replayed and what came back).
    verified: bool = False
    verification: str = ""
    created_at: datetime = Field(default_factory=_now)
