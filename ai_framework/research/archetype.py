"""App-archetype heuristics — cross-domain *priority* reuse without cross-domain *finding* reuse.

Fills the previously-empty ``ai_framework/research/`` skeleton (see this package's README).
Two domains that are the same *kind* of application (e.g. both HR/employee-management
systems with many user accounts) should benefit from the same generic testing priorities —
"check weak passwords first" — even though a fresh domain always starts its Hermes notebook
empty (``ai_framework.notebook``): no leaked findings ever cross from one target to another,
only generic heuristics keyed by archetype, not by domain.

Classification is deterministic keyword matching on the question/domain text, not an LLM
call — same rationale as ``ai_framework.supervisor``: this module never talks to an AI
provider, which is the whole point of the pivot away from an autonomous agent.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from ai_framework.taxonomy.tree import normalize_text


class ArchetypeHeuristic(BaseModel):
    archetype: str
    label: str
    keywords: tuple[str, ...] = Field(default_factory=tuple)
    priority_nodes: tuple[str, ...] = Field(default_factory=tuple)
    rationale: str = ""


# Seed set — small and easy to extend; priority_nodes are taxonomy technique node ids
# (ai_framework.taxonomy.tree.Taxonomy) so the supervisor can boost them directly.
SEED_ARCHETYPES: tuple[ArchetypeHeuristic, ...] = (
    ArchetypeHeuristic(
        archetype="hr-employee-management",
        label="HR / employee management",
        keywords=(
            "hr", "human resources", "employee", "payroll", "nhân sự", "lương", "chấm công",
        ),
        priority_nodes=("broken_authentication", "broken_access_control"),
        rationale="many named accounts -> weak-password/credential-stuffing and IDOR across "
        "employee records are disproportionately likely to pay off first",
    ),
    ArchetypeHeuristic(
        archetype="ecommerce",
        label="E-commerce / retail",
        keywords=(
            "shop", "cart", "checkout", "ecommerce", "e-commerce", "order", "giỏ hàng",
            "thanh toán",
        ),
        priority_nodes=("broken_access_control", "race_condition", "cors"),
        rationale="payment/order flows concentrate IDOR and race-condition "
        "(double-spend/coupon-reuse) issues",
    ),
    ArchetypeHeuristic(
        archetype="cms-blog",
        label="CMS / content publishing",
        keywords=("cms", "blog", "wordpress", "content management", "bài viết"),
        priority_nodes=("xss", "file_upload", "ssrf"),
        rationale="rich-text/upload surfaces and outbound webhook/preview fetches are the "
        "classic CMS attack surface",
    ),
    ArchetypeHeuristic(
        archetype="api-backend",
        label="API-only backend",
        keywords=("api", "rest api", "graphql", "microservice", "backend service"),
        priority_nodes=("api_security", "broken_access_control", "graphql"),
        rationale="no UI to guide testing -> authorization and schema/introspection issues "
        "dominate",
    ),
)


class ArchetypeStore:
    """Single-JSON store of archetype heuristics, keyed by archetype (not by domain)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load_all(self) -> dict[str, ArchetypeHeuristic]:
        out = {h.archetype: h for h in SEED_ARCHETYPES}
        if not self.path.is_file():
            return out
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return out
        for row in raw.get("archetypes", []):
            try:
                heuristic = ArchetypeHeuristic.model_validate(row)
            except Exception:  # noqa: BLE001 - a malformed row is skipped, not fatal
                continue
            out[heuristic.archetype] = heuristic
        return out

    def list_all(self) -> list[ArchetypeHeuristic]:
        return sorted(self._load_all().values(), key=lambda h: h.archetype)

    def get(self, archetype: str) -> ArchetypeHeuristic | None:
        return self._load_all().get(archetype)

    def save(self, heuristic: ArchetypeHeuristic) -> None:
        """Add or override one heuristic — user overrides persist on top of the seed set."""
        all_heuristics = self._load_all()
        all_heuristics[heuristic.archetype] = heuristic
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps({"archetypes": [h.model_dump() for h in all_heuristics.values()]}),
            encoding="utf-8",
        )
        tmp.replace(self.path)

    def classify(self, text: str) -> ArchetypeHeuristic | None:
        """Deterministic keyword match; returns the highest-hit archetype, or ``None``."""
        low = normalize_text(text)
        scored = [
            (sum(1 for kw in h.keywords if normalize_text(kw) in low), h)
            for h in self._load_all().values()
        ]
        scored = [(hits, h) for hits, h in scored if hits > 0]
        if not scored:
            return None
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return scored[0][1]
