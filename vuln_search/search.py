"""Combined vuln search: rank catalog techniques, then optionally enrich with CVEs.

This is the "rank & hand off" surface the brief describes: given a free-text query (a
product fingerprint, an error string, a technology), return ordered technique candidates
from the always-available catalog, plus matching CVEs when an online lookup is requested.
The agent (``ai_framework/research/``) and ``defense/`` consume :class:`VulnCandidate`s.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from knowledge_base.index import KnowledgeBase, repo_root
from vuln_search.catalog import TechniqueCard, load_catalog
from vuln_search.cve import Cve, CveLookup

_WORD_RE = re.compile(r"[a-z0-9]+")


class VulnCandidate(BaseModel):
    """A ranked technique candidate, with the evidence that surfaced it."""

    slug: str
    title: str
    category: str
    owasp: str
    score: float
    why: str = ""


class VulnSearchResult(BaseModel):
    techniques: list[VulnCandidate] = Field(default_factory=list)
    cves: list[Cve] = Field(default_factory=list)
    online: bool = False


def _terms(q: str) -> list[str]:
    return _WORD_RE.findall(q.lower())


def _words(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def _score(card: TechniqueCard, terms: list[str]) -> tuple[float, str]:
    """Whole-word weighted match (so 'sql' does not match 'nosql')."""
    title = _words(card.title) | _words(card.slug.replace("_", " "))
    owasp = _words(card.owasp)
    summary = _words(card.summary)
    headings = _words(" ".join(card.headings))
    score = 0.0
    matched: list[str] = []
    for t in terms:
        if t in title:
            score += 6
        elif t in owasp:
            score += 4
        elif t in summary:
            score += 2
        elif t in headings:
            score += 1
        else:
            continue
        matched.append(t)
    why = "matched: " + ", ".join(sorted(set(matched))) if matched else ""
    return score, why


class VulnSearch:
    """Searches the technique catalog and (opt-in) the CVE feeds."""

    def __init__(
        self, catalog: list[TechniqueCard] | None = None, cve: CveLookup | None = None
    ) -> None:
        self.catalog = catalog if catalog is not None else load_catalog()
        self.cve = cve or CveLookup()

    def search(
        self, query: str, *, k: int = 8, online: bool = False, cve_limit: int = 10
    ) -> VulnSearchResult:
        terms = _terms(query)
        candidates: list[VulnCandidate] = []
        for card in self.catalog:
            score, why = _score(card, terms)
            if score > 0:
                candidates.append(
                    VulnCandidate(
                        slug=card.slug,
                        title=card.title,
                        category=card.category,
                        owasp=card.owasp,
                        score=score,
                        why=why,
                    )
                )
        candidates.sort(key=lambda c: (-c.score, c.title))
        cves = self.cve.lookup(query, online=online, limit=cve_limit) if query.strip() else []
        return VulnSearchResult(techniques=candidates[:k], cves=cves, online=online)


def default_search() -> VulnSearch:
    """A VulnSearch over the bundled catalog (cache under ``vuln_search/.cve_cache.jsonl``)."""
    kb = KnowledgeBase(repo_root() / "vuln_search" / "catalog").index()
    catalog = load_catalog(kb)
    cache = repo_root() / "vuln_search" / ".cve_cache.jsonl"
    return VulnSearch(catalog=catalog, cve=CveLookup(cache_path=cache))
