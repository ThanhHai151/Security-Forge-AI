"""Localization (i18n) — English ⇄ Vietnamese.

Two things are localized independently (``i18n/README.md``):

* **UI strings** — keyed locale files (``en.json`` / ``vi.json``), looked up by key with an
  English fallback so nothing is ever hard-coded in one language.
* **Content** — English is canonical; Vietnamese is served from a translation cache, or
  produced on demand via a translator (the ``models/`` backend) and then cached.

A security-term :func:`glossary` keeps recurring concepts translated consistently.
"""

from __future__ import annotations

from i18n.loader import (
    LOCALES,
    TranslationCache,
    available_locales,
    glossary,
    load_strings,
    localize_category,
    t,
)

__all__ = [
    "LOCALES",
    "TranslationCache",
    "available_locales",
    "glossary",
    "load_strings",
    "localize_category",
    "t",
]
