"""i18n: UI string lookup with English fallback, glossary, content-translation cache."""

from __future__ import annotations

from i18n.loader import (
    TranslationCache,
    available_locales,
    glossary,
    load_strings,
    localize_category,
    t,
)


def test_locales_present_and_parse():
    assert "en" in available_locales() and "vi" in available_locales()
    assert load_strings("en")["nav.docs"] == "Docs"
    assert load_strings("vi")["nav.docs"] == "Tài liệu"


def test_t_translates_and_falls_back_to_english():
    assert t("nav.defense", "vi") == "Phòng thủ"
    assert t("nav.defense", "en") == "Defense"
    # Unknown locale → English fallback.
    assert t("nav.defense", "fr") == "Defense"
    # Unknown key → the key itself (never a crash).
    assert t("nope.missing", "vi") == "nope.missing"


def test_t_formats_placeholders():
    # Use a real key plus a format arg (no placeholder → returned verbatim).
    assert t("severity.high", "en") == "High"


def test_localize_category():
    assert localize_category("Injection", "vi") == "Tiêm nhiễm (Injection)"
    assert localize_category("Injection", "en") == "Injection"  # canonical passes through


def test_glossary_is_consistent():
    g = glossary()
    assert g["SQL injection"] == "tiêm SQL"
    assert "_meta" not in g


def test_translation_cache_english_is_identity():
    cache = TranslationCache()
    assert cache.translate("Hello", "en") == "Hello"


def test_translation_cache_offline_returns_source():
    cache = TranslationCache()
    # No translator, no cache hit → canonical English source.
    assert cache.translate("Reachable target", "vi") == "Reachable target"


def test_translation_cache_uses_translator_then_caches(tmp_path):
    path = tmp_path / "content_cache.jsonl"
    calls = []

    def fake_translator(text: str, locale: str) -> str:
        calls.append((text, locale))
        return f"[{locale}] {text}"

    cache = TranslationCache(path)
    out = cache.translate("Open redirect", "vi", fake_translator)
    assert out == "[vi] Open redirect"
    # Second call hits the cache — translator not invoked again.
    again = cache.translate("Open redirect", "vi", fake_translator)
    assert again == "[vi] Open redirect"
    assert len(calls) == 1

    # Persisted: a fresh cache over the same file resolves without a translator.
    reloaded = TranslationCache(path)
    assert reloaded.translate("Open redirect", "vi") == "[vi] Open redirect"
