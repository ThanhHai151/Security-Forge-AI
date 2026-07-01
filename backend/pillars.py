"""PlatformServices — the read surfaces the HTTP API exposes for the non-agent pillars.

Wraps the knowledge base, vuln search, defense reviewer, and i18n behind small JSON-returning
methods so ``backend/app.py`` stays a thin router. Heavy objects (the indexed KB, the catalog)
are built once and reused.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from defense.review import review_path
from i18n.loader import available_locales, glossary, load_strings
from knowledge_base.index import KnowledgeBase, repo_root
from knowledge_base.render import render_markdown
from knowledge_base.search import search, search_errors
from vuln_search.catalog import load_catalog
from vuln_search.search import VulnSearch

_MAX_DEFENSE_FINDINGS = 500


class PlatformServices:
    def __init__(self, kb_root: Path | None = None) -> None:
        root = kb_root or (repo_root() / "vuln_search" / "catalog")
        self.kb = KnowledgeBase(root).index()
        self._catalog = load_catalog(self.kb)
        self.vuln = VulnSearch(catalog=self._catalog)

    # ── knowledge base ──
    def kb_list(self, locale: str = "en") -> dict[str, Any]:
        cats: dict[str, list[dict[str, Any]]] = {}
        for entry in self.kb.all(locale):
            cats.setdefault(entry.category, []).append(
                {
                    "id": entry.id,
                    "title": entry.title,
                    "summary": entry.summary,
                    "locale": entry.locale,
                    "is_troubleshooting": entry.is_troubleshooting,
                }
            )
        return {"total": len(self.kb), "categories": cats}

    def kb_doc(self, doc_id: str, locale: str = "en") -> dict[str, Any] | None:
        entry = self.kb.get(doc_id, locale)
        if not entry:
            return None
        html, toc = render_markdown(self.kb.body(doc_id, locale))
        return {
            "id": entry.id,
            "title": entry.title,
            "category": entry.category,
            "locale": entry.locale,
            "html": html,
            "toc": toc,
        }

    def kb_search(
        self, query: str, mode: str = "full", locale: str = "en", k: int = 12
    ) -> dict[str, Any]:
        fn = search_errors if mode == "errors" else search
        hits = fn(self.kb, query, k=k, locale=locale)
        return {"mode": mode, "query": query, "hits": [h.model_dump() for h in hits]}

    # ── vuln search ──
    def vuln_search(self, query: str, online: bool = False, locale: str = "en") -> dict[str, Any]:
        result = self.vuln.search(query, online=online)
        return result.model_dump()

    # ── defense ──
    def defense_review(self, path: str) -> dict[str, Any]:
        target = Path(path).expanduser()
        if not target.exists():
            return {"error": f"path not found: {path}"}
        report = review_path(target, kb=self.kb)
        data = report.model_dump()
        if len(data["findings"]) > _MAX_DEFENSE_FINDINGS:
            data["findings"] = data["findings"][:_MAX_DEFENSE_FINDINGS]
            data["truncated"] = True
        return data

    # ── i18n ──
    def i18n(self, locale: str) -> dict[str, Any]:
        strings = load_strings(locale) or load_strings("en")
        return {
            "locale": locale,
            "available": available_locales(),
            "strings": strings,
            "glossary": glossary(),
        }
