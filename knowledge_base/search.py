"""Search the indexed notes.

Two modes (the brief asks for both):

* :func:`search` — full-text across all notes, ranked by weighted term frequency
  (title ≫ headings/summary ≫ body), returning a snippet around the first match.
* :func:`search_errors` — the dedicated *troubleshooting / error* search, restricted to
  notes flagged ``is_troubleshooting`` and matching on symptom/error strings.

Pure ranking over an in-memory :class:`~knowledge_base.index.KnowledgeBase`; no I/O here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from knowledge_base.index import KbEntry, KnowledgeBase

_TITLE_WEIGHT = 8
_HEADING_WEIGHT = 4
_SUMMARY_WEIGHT = 4
_BODY_WEIGHT = 1
_WORD_RE = re.compile(r"[a-z0-9]+")


class SearchHit(BaseModel):
    """One ranked result."""

    id: str
    title: str
    category: str
    locale: str
    score: float
    snippet: str = ""


def _terms(query: str) -> list[str]:
    return _WORD_RE.findall(query.lower())


def _count(haystack: str, terms: list[str]) -> int:
    low = haystack.lower()
    return sum(low.count(term) for term in terms)


def _snippet(body: str, terms: list[str], width: int = 160) -> str:
    low = body.lower()
    pos = min((low.find(t) for t in terms if low.find(t) >= 0), default=-1)
    if pos < 0:
        return re.sub(r"\s+", " ", body[:width]).strip()
    start = max(0, pos - width // 3)
    chunk = body[start : start + width]
    chunk = re.sub(r"\s+", " ", chunk).strip()
    return ("…" if start > 0 else "") + chunk + "…"


def _score(entry: KbEntry, body: str, terms: list[str]) -> float:
    score = (
        _count(entry.title, terms) * _TITLE_WEIGHT
        + _count(" ".join(entry.headings), terms) * _HEADING_WEIGHT
        + _count(entry.summary, terms) * _SUMMARY_WEIGHT
        + _count(body, terms) * _BODY_WEIGHT
    )
    # Small bonus for matching all distinct terms (relevance over raw frequency).
    if score and all(_count(entry.title + " " + body, [t]) for t in set(terms)):
        score += 2
    return float(score)


def search(kb: KnowledgeBase, query: str, k: int = 10, locale: str = "en") -> list[SearchHit]:
    terms = _terms(query)
    if not terms:
        return []
    hits: list[SearchHit] = []
    for entry in kb.all(locale):
        body = kb.body(entry.id, entry.locale)
        s = _score(entry, body, terms)
        if s > 0:
            hits.append(
                SearchHit(
                    id=entry.id,
                    title=entry.title,
                    category=entry.category,
                    locale=entry.locale,
                    score=s,
                    snippet=_snippet(entry.summary or body, terms),
                )
            )
    hits.sort(key=lambda h: (-h.score, h.title))
    return hits[:k]


def search_errors(
    kb: KnowledgeBase, query: str, k: int = 10, locale: str = "en"
) -> list[SearchHit]:
    """The error/troubleshooting search: same ranking, restricted to troubleshooting notes.

    Degrades gracefully — if the KB has no notes flagged as troubleshooting, the full index
    is searched so the feature still returns the most relevant matches.
    """
    troubleshooting = [e for e in kb.all(locale) if e.is_troubleshooting]
    if not troubleshooting:
        return search(kb, query, k=k, locale=locale)
    terms = _terms(query)
    if not terms:
        return []
    hits: list[SearchHit] = []
    for entry in troubleshooting:
        body = kb.body(entry.id, entry.locale)
        s = _score(entry, body, terms)
        if s > 0:
            hits.append(
                SearchHit(
                    id=entry.id,
                    title=entry.title,
                    category=entry.category,
                    locale=entry.locale,
                    score=s,
                    snippet=_snippet(body, terms),
                )
            )
    hits.sort(key=lambda h: (-h.score, h.title))
    return hits[:k]
