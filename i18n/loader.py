"""Load locale files, look strings up, and cache content translations.

UI lookups (:func:`t`) fall back to English when a key is missing in the target locale —
the i18n contract: nothing user-facing is hard-coded in one language. Content translation
(:class:`TranslationCache`) is offline-graceful: with no translator it returns the English
source unchanged, so the product still renders without a model backend.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from functools import cache, lru_cache
from pathlib import Path

I18N_DIR = Path(__file__).resolve().parent
LOCALES = ("en", "vi")
DEFAULT_LOCALE = "en"

Translator = Callable[[str, str], str]  # (text, target_locale) -> translated text


@cache
def load_strings(locale: str) -> dict[str, str]:
    """All UI strings for a locale (``_meta`` stripped). Unknown/invalid locale → empty dict.

    ``locale`` is untrusted URL input (``GET /i18n/{locale}``). It is checked against the fixed
    ``LOCALES`` allow-list, never mapped to an arbitrary path — so ``../ai_accounts`` and any
    other traversal cannot read a file outside the locale set. (ARCHITECTURE.md P0.)
    """
    if locale not in LOCALES:
        return {}
    path = I18N_DIR / f"{locale}.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if k != "_meta"}


def available_locales() -> list[str]:
    return [loc for loc in LOCALES if (I18N_DIR / f"{loc}.json").is_file()]


def t(key: str, locale: str = DEFAULT_LOCALE, **fmt: object) -> str:
    """Translate a UI key, English-fallback, then the key itself. ``**fmt`` runs ``str.format``."""
    value = load_strings(locale).get(key)
    if value is None and locale != DEFAULT_LOCALE:
        value = load_strings(DEFAULT_LOCALE).get(key)
    if value is None:
        value = key
    return value.format(**fmt) if fmt else value


def localize_category(name: str, locale: str = DEFAULT_LOCALE) -> str:
    """Localize a catalog category name (English passes through)."""
    return t(f"category.{name}", locale) if locale != DEFAULT_LOCALE else name


@lru_cache(maxsize=1)
def glossary() -> dict[str, str]:
    path = I18N_DIR / "glossary.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if k != "_meta"}


def _key(text: str, locale: str) -> str:
    return hashlib.sha256(f"{locale}\x00{text}".encode()).hexdigest()


class TranslationCache:
    """A persistent cache of content translations (the i18n 'translation-cache layout').

    Layout: JSON-lines of ``{key, locale, source, translated}`` so a piece of content is
    translated once and reused. English is never translated (it's canonical).
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._mem: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                self._mem[rec["key"]] = rec["translated"]

    def get(self, text: str, locale: str) -> str | None:
        return self._mem.get(_key(text, locale))

    def put(self, text: str, locale: str, translated: str) -> None:
        key = _key(text, locale)
        self._mem[key] = translated
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            rec = {"key": key, "locale": locale, "source": text, "translated": translated}
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def translate(self, text: str, locale: str, translator: Translator | None = None) -> str:
        """Cache-first content translation. English source returns unchanged.

        With no ``translator`` and no cache hit, returns the English source (offline-graceful
        degradation per the integration plan).
        """
        if locale == DEFAULT_LOCALE or not text.strip():
            return text
        cached = self.get(text, locale)
        if cached is not None:
            return cached
        if translator is None:
            return text  # offline: fall back to canonical English
        translated = translator(text, locale)
        self.put(text, locale, translated)
        return translated
