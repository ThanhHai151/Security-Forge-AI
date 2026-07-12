"""Persistent findings store — JSON-lines, mirroring the memory store's shape.

Findings are appended as they are captured so they survive a run and can be listed in the UI
or exported to a report. Reads offer the two slices the product needs: everything for one run
(the report) and everything for one target (the running picture), plus a small summary for the
findings view.
"""

from __future__ import annotations

import json
from pathlib import Path

from ai_framework.notes.contracts import Finding
from ai_framework.security.redaction import redact_data


class JsonlFindingStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, finding: Finding) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(redact_data(finding.model_dump(mode="json"))) + "\n")

    def all(self) -> list[Finding]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [Finding.model_validate_json(line) for line in fh if line.strip()]

    def for_run(self, run_id: str) -> list[Finding]:
        return [f for f in self.all() if f.run_id == run_id]

    def for_target(self, target: str) -> list[Finding]:
        return [f for f in self.all() if f.target == target]

    def summary(self, target: str = "") -> dict:
        """Counts by severity + recent findings — backs the findings view UI."""
        findings = self.for_target(target) if target else self.all()
        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity.name] = by_severity.get(f.severity.name, 0) + 1
        recent = sorted(findings, key=lambda f: f.created_at.isoformat(), reverse=True)[:20]
        return {
            "total": len(findings),
            "by_severity": by_severity,
            "targets": sorted({f.target for f in findings if f.target}),
            "recent": [
                {
                    "id": f.id,
                    "run_id": f.run_id,
                    "target": f.target,
                    "title": f.title,
                    "severity": f.severity.name,
                    "detail": f.detail,
                    "created_at": f.created_at.isoformat(),
                }
                for f in recent
            ],
        }

    @staticmethod
    def ranked(findings: list[Finding]) -> list[Finding]:
        """Worst-first, then most-recent — the order a report should present them."""
        return sorted(
            findings, key=lambda f: (int(f.severity), f.created_at.isoformat()), reverse=True
        )
