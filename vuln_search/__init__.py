"""Vulnerability Search (Pillar 3).

Answers "what could be wrong here?" from two sources: the bundled **technique catalog**
(the documented vuln classes, searched offline-first) and an **opt-in CVE lookup** for
unfamiliar technologies. Ranks both and hands candidates to ``ai_framework`` and
``defense``. See ``vuln_search/README.md`` and ``ARCHITECTURE.md`` › Vuln Search.
"""

from __future__ import annotations

from vuln_search.catalog import TechniqueCard, load_catalog
from vuln_search.cve import Cve, CveLookup, seed_from_catalog
from vuln_search.search import VulnCandidate, VulnSearch, default_search

__all__ = [
    "TechniqueCard",
    "load_catalog",
    "Cve",
    "CveLookup",
    "seed_from_catalog",
    "VulnCandidate",
    "VulnSearch",
    "default_search",
]
