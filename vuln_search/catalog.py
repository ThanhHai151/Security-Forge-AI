"""The technique catalog — the documented vuln classes, as searchable cards.

Loads ``vuln_search/catalog/`` via the shared :class:`~knowledge_base.index.KnowledgeBase`
(one folder per class, ``<slug>/README.md``), enriching each with the card's OWASP/aliases
line and completion status. ``INDEX.md`` supplies the canonical category order. This is the
primary, always-available search source — no network required.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from knowledge_base.index import KnowledgeBase, repo_root

_META_RE = re.compile(r"^\*\*([^:*]+):\*\*\s*(.+)$")


class TechniqueCard(BaseModel):
    """One vulnerability class in the catalog."""

    slug: str
    title: str
    category: str = ""
    owasp: str = ""  # aliases / OWASP category line
    status: str = ""  # complete | stub
    summary: str = ""
    headings: list[str] = Field(default_factory=list)
    has_vi: bool = False
    kb_id: str  # id into the KnowledgeBase (e.g. "sql_injection")


def _meta(text: str, keys: tuple[str, ...]) -> str:
    """Pull a ``**Key:** value`` line out of a card header, links/backticks stripped."""
    for line in text.splitlines():
        m = _META_RE.match(line.strip())
        if m and any(k in m.group(1).lower() for k in keys):
            val = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", m.group(2))
            return re.sub(r"[`*]", "", val).strip()
    return ""


def _index_categories(index_md: str) -> dict[str, str]:
    """Map each slug to its INDEX.md category heading (canonical grouping)."""
    out: dict[str, str] = {}
    cur = ""
    for line in index_md.splitlines():
        h = re.match(r"^##\s+(.+?)\s*$", line)
        if h:
            cur = h.group(1).strip()
            continue
        link = re.search(r"\((\w[\w-]*)/README\.md\)", line)
        if link and cur:
            out[link.group(1)] = cur
    return out


def _catalog_root() -> Path:
    return repo_root() / "vuln_search" / "catalog"


def load_catalog(kb: KnowledgeBase | None = None) -> list[TechniqueCard]:
    """Build the ordered list of technique cards from the catalog directory."""
    root = _catalog_root()
    kb = kb or KnowledgeBase(root).index()
    index_md = ""
    index_path = root / "INDEX.md"
    if index_path.is_file():
        index_md = index_path.read_text(encoding="utf-8")
    categories = _index_categories(index_md)

    cards: list[TechniqueCard] = []
    for entry in kb.all("en"):
        slug = entry.id
        if slug in {"INDEX", "ENTRY_TEMPLATE"} or "/" in slug:
            continue  # skip the index + template, keep only "<slug>" folder cards
        body = kb.body(slug, "en")
        owasp = _meta(body, ("owasp", "aliases"))
        status_raw = _meta(body, ("status",)).lower()
        status = "stub" if "stub" in status_raw else ("complete" if status_raw else "")
        vi = kb.get(slug, "vi")
        cards.append(
            TechniqueCard(
                slug=slug,
                title=entry.title,
                category=categories.get(slug, entry.category),
                owasp=owasp,
                status=status,
                summary=entry.summary,
                headings=entry.headings,
                has_vi=vi is not None and vi.locale == "vi",
                kb_id=slug,
            )
        )
    # Order by INDEX position when known, else alphabetically.
    order = {slug: i for i, slug in enumerate(categories)}
    cards.sort(key=lambda c: (order.get(c.slug, len(order)), c.title))
    return cards
