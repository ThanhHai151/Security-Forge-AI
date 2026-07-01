"""Vuln Search: catalog loading + offline-first CVE lookup + combined ranking."""

from __future__ import annotations

import json

from vuln_search.catalog import load_catalog
from vuln_search.cve import Cve, CveLookup, seed_from_catalog
from vuln_search.search import VulnSearch, default_search


# ── catalog ──
def test_catalog_loads_real_cards():
    cards = load_catalog()
    assert len(cards) >= 20
    by_slug = {c.slug for c in cards}
    assert {"sql_injection", "xss", "ssrf"} <= by_slug
    # INDEX/template are not cards.
    assert "INDEX" not in by_slug and "ENTRY_TEMPLATE" not in by_slug


def test_catalog_card_has_metadata():
    sqli = next(c for c in load_catalog() if c.slug == "sql_injection")
    assert "SQL" in sqli.title
    assert "A03" in sqli.owasp  # OWASP line parsed
    assert sqli.status == "complete"
    assert sqli.category  # placed into an INDEX category
    assert sqli.has_vi is True  # README.vi.md exists


# ── CVE seed + lookup ──
def test_seed_parses_notable_cves_from_catalog():
    seeds = seed_from_catalog()
    ids = {c.id for c in seeds}
    assert "CVE-2023-34362" in ids  # MOVEit SQLi, written in the sql_injection card
    assert all(c.source == "seed" for c in seeds)


def test_lookup_offline_matches_seed():
    lookup = CveLookup()
    hits = lookup.lookup("sql injection")
    assert hits
    assert any(h.id == "CVE-2023-34362" for h in hits)


def test_lookup_uses_cache(tmp_path):
    cache = tmp_path / "cve.jsonl"
    cache.write_text(
        Cve(id="CVE-2099-0001", summary="cached widget rce", keywords=["widget"]).model_dump_json()
        + "\n",
        encoding="utf-8",
    )
    hits = CveLookup(seed=[], cache_path=cache).lookup("widget")
    assert hits and hits[0].id == "CVE-2099-0001"
    assert hits[0].source == "cache"


def test_lookup_online_fetches_parses_and_caches(tmp_path):
    payload = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-12345",
                        "descriptions": [{"lang": "en", "value": "ACME router command injection"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                        "references": [{"url": "https://example.com/adv"}],
                    }
                }
            ]
        }
    ).encode()
    cache = tmp_path / "cve.jsonl"
    lookup = CveLookup(seed=[], cache_path=cache, fetcher=lambda url: payload)
    hits = lookup.lookup("acme router", online=True)
    assert hits[0].id == "CVE-2024-12345"
    assert hits[0].severity == "HIGH"
    assert hits[0].source == "nvd"
    # Cached for next time — a second offline lookup still finds it.
    reloaded = CveLookup(seed=[], cache_path=cache).lookup("acme")
    assert any(h.id == "CVE-2024-12345" for h in reloaded)


def test_lookup_online_degrades_when_fetch_fails():
    def boom(url: str) -> bytes:
        raise OSError("network unreachable")

    lookup = CveLookup(seed=[], fetcher=boom)
    assert lookup.lookup("anything", online=True) == []  # no crash, empty result


# ── combined search ──
def test_search_ranks_relevant_techniques_first():
    vs = VulnSearch()
    result = vs.search("sql injection in login form")
    assert result.techniques
    assert result.techniques[0].slug == "sql_injection"
    assert "matched" in result.techniques[0].why


def test_search_includes_seed_cves_offline():
    vs = VulnSearch()
    result = vs.search("sql injection")
    assert any(c.id == "CVE-2023-34362" for c in result.cves)
    assert result.online is False


def test_default_search_is_usable():
    vs = default_search()
    result = vs.search("server side request forgery")
    assert result.techniques and result.techniques[0].slug == "ssrf"
