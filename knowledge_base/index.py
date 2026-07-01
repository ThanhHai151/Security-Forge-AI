"""Index markdown notes into searchable entries.

``KnowledgeBase.index(root)`` walks a markdown tree once, recording one :class:`KbEntry`
per *(document, language)* pair — id, path, title, category, headings, troubleshooting
flag, locale, size. English is canonical; a ``*.vi.md`` sibling is the Vietnamese variant
of the same document id (i18n rule). Non-content directories are skipped. The index never
modifies the source notes.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

# Directories that never hold knowledge content — skipped during the walk.
SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", ".claude", ".serena", "node_modules", "__pycache__", "dist",
     ".pytest_cache", ".github", ".mypy_cache", ".ruff_cache"}
)
# A document is "troubleshooting" if its path mentions these (the brief's error search).
_TROUBLESHOOT_HINTS = ("troubleshoot", "error", "debug", "fix")

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_CODE_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_LOCALE_RE = re.compile(r"\.([a-z]{2})\.md$", re.IGNORECASE)


class KbEntry(BaseModel):
    """One indexed note, in one language."""

    id: str  # stable doc id (the relative path without extension/locale), e.g. "sql_injection"
    locale: str = "en"
    path: str  # repo-relative source path, e.g. "vuln_search/catalog/sql_injection/README.md"
    title: str = ""
    category: str = ""  # top-level folder under the KB root
    summary: str = ""  # leading blockquote, plain text
    headings: list[str] = Field(default_factory=list)
    is_troubleshooting: bool = False
    size: int = 0


def _slug_and_locale(rel: Path) -> tuple[str, str]:
    """Map a relative md path to a stable doc id + locale.

    ``a/b/README.md`` -> id ``a/b``, locale ``en``.
    ``a/b/README.vi.md`` -> id ``a/b``, locale ``vi``.
    ``a/b/note.md`` -> id ``a/b/note``, locale ``en``.
    """
    name = rel.name
    locale = "en"
    m = _LOCALE_RE.search(name)
    if m:
        locale = m.group(1).lower()
        stem = name[: m.start()]
    else:
        stem = name[: -len(".md")] if name.lower().endswith(".md") else name
    parent = rel.parent
    # README is the folder's canonical doc → id is the folder path itself.
    if stem.lower() == "readme":
        doc_id = parent.as_posix()
    else:
        doc_id = (parent / stem).as_posix()
    doc_id = doc_id.strip("/") or stem
    return doc_id, locale


def parse_markdown(text: str) -> tuple[str, str, list[str]]:
    """Extract (title, summary, headings) from markdown, ignoring fenced code blocks."""
    title = ""
    summary_lines: list[str] = []
    headings: list[str] = []
    in_fence = False
    seen_title = False
    collecting_summary = False
    for line in text.splitlines():
        if _CODE_FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        h = _HEADING_RE.match(line)
        if h:
            heading_text = h.group(2).strip()
            if not seen_title and len(h.group(1)) == 1:
                title = heading_text
                seen_title = True
                collecting_summary = True
            else:
                headings.append(heading_text)
                collecting_summary = False
            continue
        if collecting_summary and line.lstrip().startswith(">"):
            summary_lines.append(line.lstrip()[1:].strip())
    summary = _clean_inline(" ".join(s for s in summary_lines if s))
    return title, summary, headings


_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def _clean_inline(text: str) -> str:
    """Strip markdown emphasis/links/code markers for a plain-text summary."""
    text = _LINK_RE.sub(r"\1", text)
    text = re.sub(r"[*_`]+", "", text)
    # Stop the summary at the first metadata break ("Deep dive:", "Tài liệu", etc.).
    text = re.split(r"\s*(?:Deep dive|Tài liệu)\b", text)[0]
    return re.sub(r"\s+", " ", text).strip()


class KnowledgeBase:
    """An in-memory index over a markdown tree. Read-only over the source notes."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self._entries: dict[tuple[str, str], KbEntry] = {}  # (id, locale) -> entry
        self._bodies: dict[tuple[str, str], str] = {}

    def index(self) -> KnowledgeBase:
        """Walk the root, (re)building the index. Returns self for chaining."""
        self._entries.clear()
        self._bodies.clear()
        if not self.root.is_dir():
            return self
        for path in sorted(self.root.rglob("*.md")):
            if any(part in SKIP_DIRS for part in path.relative_to(self.root).parts):
                continue
            self._add(path)
        return self

    def _add(self, path: Path) -> None:
        rel = path.relative_to(self.root)
        doc_id, locale = _slug_and_locale(rel)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        title, summary, headings = parse_markdown(text)
        category = rel.parts[0] if len(rel.parts) > 1 else "root"
        rel_posix = rel.as_posix()
        is_ts = any(h in rel_posix.lower() or h in category.lower() for h in _TROUBLESHOOT_HINTS)
        entry = KbEntry(
            id=doc_id,
            locale=locale,
            path=(self.root.name + "/" + rel_posix),
            title=title or doc_id,
            category=category,
            summary=summary,
            headings=headings,
            is_troubleshooting=is_ts,
            size=len(text),
        )
        self._entries[(doc_id, locale)] = entry
        self._bodies[(doc_id, locale)] = text

    # ── access ──
    def all(self, locale: str = "en") -> list[KbEntry]:
        """Every document in ``locale`` (English fallback when a translation is absent)."""
        ids = {doc_id for (doc_id, _loc) in self._entries}
        return [e for e in (self.get(doc_id, locale) for doc_id in sorted(ids)) if e]

    def get(self, doc_id: str, locale: str = "en") -> KbEntry | None:
        """An entry by id, falling back to English then any available locale (i18n rule)."""
        for loc in (locale, "en"):
            if (doc_id, loc) in self._entries:
                return self._entries[(doc_id, loc)]
        for (did, _loc), entry in self._entries.items():
            if did == doc_id:
                return entry
        return None

    def body(self, doc_id: str, locale: str = "en") -> str:
        for loc in (locale, "en"):
            if (doc_id, loc) in self._bodies:
                return self._bodies[(doc_id, loc)]
        for (did, _loc), text in self._bodies.items():
            if did == doc_id:
                return text
        return ""

    def categories(self, locale: str = "en") -> dict[str, list[KbEntry]]:
        out: dict[str, list[KbEntry]] = {}
        for entry in self.all(locale):
            out.setdefault(entry.category, []).append(entry)
        return out

    def __len__(self) -> int:
        return len({doc_id for (doc_id, _loc) in self._entries})


def section(body: str, heading: str) -> str:
    """Return the markdown text under a ``## heading`` up to the next heading of any level.

    Shared by ``vuln_search`` (the 'Notable CVEs' seed) and ``defense`` (the 'Defenses'
    guidance) so both read the catalog the same way.
    """
    out: list[str] = []
    capturing = False
    for line in body.splitlines():
        h = _HEADING_RE.match(line)
        if h:
            capturing = len(h.group(1)) <= 2 and heading.lower() in h.group(2).lower()
            continue
        if capturing:
            out.append(line)
    return "\n".join(out).strip()


def repo_root() -> Path:
    """The project root (parent of this package)."""
    return Path(__file__).resolve().parents[1]


def default_kb() -> KnowledgeBase:
    """The KB over the bundled vulnerability catalog — the always-present content source."""
    return KnowledgeBase(repo_root() / "vuln_search" / "catalog").index()
