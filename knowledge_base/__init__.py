"""Knowledge Base (Pillar 1, data side).

Indexes the repository's markdown notes into searchable :class:`KbEntry` records,
renders them to **safe** HTML (payloads are escaped so the viewer never executes them),
and searches them two ways (full-text + troubleshooting/error). The backend serves this;
``vuln_search`` and ``defense`` query it; the ``frontend`` renders it. See
``knowledge_base/README.md`` and ``ARCHITECTURE.md`` › Knowledge Base.
"""

from __future__ import annotations

from knowledge_base.index import KbEntry, KnowledgeBase, default_kb
from knowledge_base.render import render_markdown
from knowledge_base.search import SearchHit, search, search_errors

__all__ = [
    "KbEntry",
    "KnowledgeBase",
    "default_kb",
    "render_markdown",
    "SearchHit",
    "search",
    "search_errors",
]
