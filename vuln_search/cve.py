"""CVE lookup — offline-first, online opt-in.

Three layers, in order of cost:

1. **Offline seed** — the "Notable CVEs" already written into the catalog cards, parsed into
   records keyed by the class keywords. Always available, no network.
2. **On-disk cache** — JSON-lines of anything fetched live, so a query is paid for once.
3. **Live query** — opt-in NVD keyword search, wrapped so a missing network / blocked egress
   degrades to the seed + cache instead of raising. The fetcher is injectable for testing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from pydantic import BaseModel, Field

from knowledge_base.index import KnowledgeBase, repo_root, section

_CVE_LINE_RE = re.compile(r"`?(CVE-\d{4}-\d{3,7})`?\s*[—–-]\s*(.+)")
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage={}"

Fetcher = Callable[[str], bytes]


class Cve(BaseModel):
    """A single vulnerability record (normalized across sources)."""

    id: str
    summary: str = ""
    source: str = "seed"  # seed | cache | nvd
    severity: str = ""
    references: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)


def _keywords(title: str, owasp: str) -> list[str]:
    text = f"{title} {owasp}".lower()
    words = re.findall(r"[a-z0-9]{3,}", text)
    stop = {"the", "and", "for", "with", "vulnerabilities", "vulnerability", "attacks", "owasp"}
    return sorted({w for w in words if w not in stop})


def seed_from_catalog(kb: KnowledgeBase | None = None) -> list[Cve]:
    """Parse every card's '## Notable CVEs' section into seed records."""
    root = repo_root() / "vuln_search" / "catalog"
    kb = kb or KnowledgeBase(root).index()
    seeds: list[Cve] = []
    for entry in kb.all("en"):
        if "/" in entry.id or entry.id in {"INDEX", "ENTRY_TEMPLATE"}:
            continue
        body = kb.body(entry.id, "en")
        notable = section(body, "Notable CVEs")
        kws = _keywords(entry.title, entry.id.replace("_", " "))
        for line in notable.splitlines():
            m = _CVE_LINE_RE.search(line.strip().lstrip("-").strip())
            if m:
                summary = re.sub(r"[`*]", "", m.group(2)).strip()
                seeds.append(Cve(id=m.group(1), summary=summary, source="seed", keywords=kws))
    return seeds


class CveLookup:
    """Search CVEs across the seed, the cache, and (opt-in) a live source."""

    def __init__(
        self,
        seed: list[Cve] | None = None,
        cache_path: str | Path | None = None,
        fetcher: Fetcher | None = None,
    ) -> None:
        self._seed = seed if seed is not None else seed_from_catalog()
        self.cache_path = Path(cache_path) if cache_path else None
        self._fetcher = fetcher or _default_fetcher

    # ── public ──
    def lookup(self, query: str, *, online: bool = False, limit: int = 10) -> list[Cve]:
        terms = re.findall(r"[a-z0-9]{2,}", query.lower())
        results: dict[str, Cve] = {}
        for cve in self._seed + self._read_cache():
            if self._matches(cve, terms, query):
                results.setdefault(cve.id, cve)
        if online:
            for cve in self._live(query, limit):
                results.setdefault(cve.id, cve)
        ordered = sorted(results.values(), key=lambda c: c.id, reverse=True)
        return ordered[:limit]

    # ── matching ──
    @staticmethod
    def _matches(cve: Cve, terms: list[str], raw: str) -> bool:
        if not terms:
            return False
        hay = f"{cve.id} {cve.summary} {' '.join(cve.keywords)}".lower()
        if raw.strip().lower() in hay:
            return True
        return any(t in hay for t in terms)

    # ── cache ──
    def _read_cache(self) -> list[Cve]:
        if not self.cache_path or not self.cache_path.exists():
            return []
        out: list[Cve] = []
        for line in self.cache_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                cve = Cve.model_validate_json(line)
                cve.source = "cache"
                out.append(cve)
        return out

    def _write_cache(self, cves: list[Cve]) -> None:
        if not self.cache_path or not cves:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        existing = {c.id for c in self._read_cache()}
        with self.cache_path.open("a", encoding="utf-8") as fh:
            for cve in cves:
                if cve.id not in existing:
                    fh.write(cve.model_dump_json() + "\n")

    # ── live (opt-in, offline-graceful) ──
    def _live(self, query: str, limit: int) -> list[Cve]:
        url = _NVD_URL.format(quote(query), max(1, min(limit, 20)))
        try:
            raw = self._fetcher(url)
            cves = _parse_nvd(raw)
        except Exception:  # noqa: BLE001 - offline / blocked / malformed → degrade silently
            return []
        self._write_cache(cves)
        return cves


def _default_fetcher(url: str) -> bytes:
    with urlopen(Request(url, headers={"User-Agent": "secforge"}), timeout=10) as resp:  # noqa: S310
        return resp.read()


def _parse_nvd(raw: bytes) -> list[Cve]:
    data = json.loads(raw)
    out: list[Cve] = []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cid = c.get("id", "")
        if not cid:
            continue
        descs = c.get("descriptions", [])
        summary = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        metrics = c.get("metrics", {})
        severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "") or severity
        refs = [r.get("url", "") for r in c.get("references", []) if r.get("url")]
        out.append(Cve(id=cid, summary=summary, source="nvd", severity=severity, references=refs))
    return out
