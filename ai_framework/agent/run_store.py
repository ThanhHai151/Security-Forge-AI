"""Durable run storage — checkpoint each run's transcript to disk so it survives a restart.

hermes-agent keeps sessions in SQLite; SecForge stays lean with one JSON file per run under a
directory. The loop calls ``save`` after every turn (via its ``on_turn`` hook), so an
in-flight run is recoverable and a finished run can be reloaded, replayed, or exported to a
report without keeping it in memory. Reads are cheap because each run is a self-contained file.
"""

from __future__ import annotations

import json
from pathlib import Path

from ai_framework.agent.contracts import Run
from ai_framework.security.redaction import redact_data


class JsonRunStore:
    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)

    def _path(self, run_id: str) -> Path:
        return self.dir / f"{run_id}.json"

    def save(self, run: Run) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        # Write-then-rename so a concurrent reader never sees a half-written file.
        tmp = self._path(run.id).with_suffix(".json.tmp")
        data = redact_data(run.model_dump(mode="json"))
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._path(run.id))

    def load(self, run_id: str) -> Run | None:
        path = self._path(run_id)
        if not path.is_file():
            return None
        return Run.model_validate_json(path.read_text(encoding="utf-8"))

    def list_runs(self) -> list[dict]:
        """Lightweight summaries (id, goal, target, outcome, turns), newest file first."""
        if not self.dir.is_dir():
            return []
        out: list[dict] = []
        for path in sorted(self.dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            cfg = data.get("config", {})
            out.append(
                {
                    "id": data.get("id", path.stem),
                    "goal": cfg.get("goal", ""),
                    "target": cfg.get("target", ""),
                    "backend": cfg.get("backend", ""),
                    "outcome": data.get("outcome", ""),
                    "turns": len(data.get("transcript", [])),
                }
            )
        return out
