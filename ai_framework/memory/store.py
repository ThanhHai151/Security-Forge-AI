"""Persistent, cross-session memory (Hermes-style).

Records are appended to a JSON-lines file so memory outlives a single run. ``recall``
ranks by (target match, technique match, recency) and returns the top-K to re-enter the
loop's context. ``has_failed_attempt`` backs the anti-loop guard. See §2.4 and Step 5.
"""

from __future__ import annotations

from pathlib import Path

from ai_framework.agent.contracts import MemoryKind, MemoryRecord


class JsonlMemoryStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, record: MemoryRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")

    def all(self) -> list[MemoryRecord]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [MemoryRecord.model_validate_json(line) for line in fh if line.strip()]

    def recall(self, target: str, technique: str, k: int = 5) -> list[MemoryRecord]:
        records = self.all()

        def score(r: MemoryRecord) -> tuple[int, int, str]:
            return (
                1 if r.target == target else 0,
                1 if technique and r.technique == technique else 0,
                r.created_at.isoformat(),  # recency: later isoformat sorts higher
            )

        ranked = sorted(records, key=score, reverse=True)
        # Organize before returning: dedupe + fold attempt-spam so recall stays token-light
        # (Headroom can still shrink K further if the window is tight).
        from ai_framework.headroom.compress import consolidate_memory

        return consolidate_memory(ranked)[:k]

    def summary(self, target: str = "") -> dict:
        """What the agent has learned (optionally for one target) — for the memory view UI."""
        records = self.all()
        if target:
            records = [r for r in records if r.target == target]
        by_kind: dict[str, int] = {}
        targets: set[str] = set()
        for r in records:
            by_kind[str(r.kind)] = by_kind.get(str(r.kind), 0) + 1
            if r.target:
                targets.add(r.target)
        recent = sorted(records, key=lambda r: r.created_at.isoformat(), reverse=True)[:20]
        return {
            "total": len(records),
            "by_kind": by_kind,
            "targets": sorted(targets),
            "recent": [
                {
                    "kind": str(r.kind),
                    "target": r.target,
                    "technique": r.technique,
                    "body": r.body,
                    "created_at": r.created_at.isoformat(),
                }
                for r in recent
            ],
        }

    def has_failed_attempt(self, target: str, technique: str, body: str) -> bool:
        return any(
            r.kind == MemoryKind.attempt
            and r.target == target
            and r.technique == technique
            and r.body == body
            for r in self.all()
        )
