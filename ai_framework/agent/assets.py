"""Asset graph — the structured recon picture the agent builds as it explores.

Free-text memory is good for lessons; it's poor for "what endpoints/params/tech have I found?".
This store captures discovered **assets** as typed records so later reasoning (and the report)
can work over structure instead of prose: endpoints, parameters, forms, technologies, hosts,
and subdomains, each with the target it belongs to and how it was found.

The ``record_asset`` tool appends to it (the loop persists successful calls, exactly like
``note_finding``), and :meth:`summary` backs a recon view / API route. JSON-lines, mirroring
the memory and findings stores.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from ai_framework.security.fsutil import open_private_append
from ai_framework.security.redaction import redact_data

ASSET_KINDS = ("endpoint", "param", "form", "tech", "host", "subdomain", "cookie", "other")


def _now() -> datetime:
    return datetime.now(UTC)


class Asset(BaseModel):
    """One discovered piece of attack surface."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    target: str = ""
    kind: str = "other"  # one of ASSET_KINDS
    value: str = ""      # the URL / param name / tech string / host
    detail: str = ""     # how it was found or extra context
    source: str = ""     # tool/step that discovered it
    created_at: datetime = Field(default_factory=_now)

    @staticmethod
    def normalize_kind(kind: object) -> str:
        k = str(kind or "").strip().lower()
        return k if k in ASSET_KINDS else "other"


class JsonlAssetStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, asset: Asset) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open_private_append(self.path) as fh:
            fh.write(json.dumps(redact_data(asset.model_dump(mode="json"))) + "\n")

    def all(self) -> list[Asset]:
        if not self.path.exists():
            return []
        # Tolerate a truncated final line (e.g. a crash mid-append) or a malformed row instead of
        # raising — a single bad line must not take down the whole recon view.
        out: list[Asset] = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    out.append(Asset.model_validate_json(line))
                except ValueError:
                    continue
        return out

    def for_target(self, target: str) -> list[Asset]:
        return [a for a in self.all() if a.target == target]

    def summary(self, target: str = "") -> dict:
        """Counts by kind + deduped values per kind + recent — backs the recon view."""
        assets = self.for_target(target) if target else self.all()
        by_kind: dict[str, int] = {}
        values: dict[str, list[str]] = {}
        for a in assets:
            by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
            bucket = values.setdefault(a.kind, [])
            if a.value and a.value not in bucket:
                bucket.append(a.value)
        recent = sorted(assets, key=lambda a: a.created_at.isoformat(), reverse=True)[:30]
        return {
            "total": len(assets),
            "by_kind": by_kind,
            "values": values,
            "targets": sorted({a.target for a in assets if a.target}),
            "recent": [
                {"id": a.id, "target": a.target, "kind": a.kind, "value": a.value,
                 "detail": a.detail, "source": a.source, "created_at": a.created_at.isoformat()}
                for a in recent
            ],
        }
