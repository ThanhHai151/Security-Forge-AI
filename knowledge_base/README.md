# `knowledge_base/` — Index, Render & Search the Notes

**Pillar 1 (data).** Turns the repository's ~278 `.md` files into something the
[`frontend/`](../frontend/README.md) can display beautifully and everything else can query.
This is the shared reference surface other pillars link into.

## Responsibilities

- **Index** — scan the knowledge-base root (the CTF repo's topic folders), recording one
  entry per note: id, path, title, category, headings, whether it is a
  troubleshooting/error doc, size, modified time. Skips non-content dirs (`.venv`,
  `.claude`, `.git`, `secforge`) and empty placeholders.
- **Render** — convert markdown to **safe** HTML. *Security-critical:* the notes contain
  live XSS/SQLi payloads, so every code block and inline span must be HTML-escaped or the
  viewer itself becomes vulnerable. Supports headings (with anchors for a TOC), fenced code
  with language hints, tables, lists, blockquotes, rules, and inline formatting.
- **Search** — two modes:
  - **full-text** across all notes, ranked;
  - **errors/troubleshooting** — the dedicated "search for errors" feature, focused on the
    `Troubleshooting_Guide/` notes and matching on symptoms/error strings.

## Connects to

- [`../frontend/`](../frontend/README.md) renders what this produces.
- [`../vuln_search/`](../vuln_search/README.md) searches this index as its first source.
- [`../ai_framework/skills/`](../ai_framework/skills/README.md) — each KB topic backs a skill.
- [`../i18n/`](../i18n/README.md) — content is tagged with a language so the viewer can
  request EN or VI.

## Content source

Read-only over a markdown root (default:
[`../vuln_search/catalog/`](../vuln_search/catalog/INDEX.md), the bundled vulnerability
dictionary). Point it at any markdown tree (e.g. a CTF repo's `SQL/`, `XSS/`,
`Troubleshooting_Guide/` folders). This pillar never modifies the source notes.

## Implementation

- [`index.py`](index.py) — `KnowledgeBase.index()` walks a root into `KbEntry` records
  (id, locale, title, category, headings, troubleshooting flag, size), grouping `*.vi.md`
  siblings under one doc id and skipping non-content dirs; `default_kb()` indexes the catalog.
- [`render.py`](render.py) — `render_markdown()` → **safe** HTML (every payload escaped,
  headings get TOC anchors, `javascript:` link targets dropped) plus a table-of-contents list.
- [`search.py`](search.py) — `search()` (weighted full-text) and `search_errors()`
  (troubleshooting-restricted), both ranked.

Served by the backend at `GET /kb`, `/kb/doc/{id}`, `/kb/search`.

**Status:** implemented — indexer + safe renderer + search, with tests
(`tests/test_knowledge_base.py`).
