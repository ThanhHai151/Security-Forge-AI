# `frontend/` — The Viewer & Console UI

**Pillar 1 (presentation).** The single-page console the user actually looks at. Its first
job is to display the knowledge base far more readably than raw `.md` — the feel of a web
app or Notion.

> **Status:** the **Knowledge Base viewer** is implemented (React + Vite + Tailwind v4).
> It reads the vulnerability dictionary from [`../vuln_search/catalog/`](../vuln_search/catalog/INDEX.md)
> and renders it with category navigation, a per-page table of contents, syntax-highlighted
> payloads, search, and an EN ⇄ VI toggle. The other pillar tabs (Agent Console, Defense,
> Labs) are not built yet.

## Run it

```bash
cd frontend
npm install
npm run dev        # http://localhost:61020
npm run build      # production bundle in dist/
```

Ports follow a **+1 convention**: the frontend runs on **61020** and the backend API on
**61021** (`61020 + 1`). The dev server proxies `/api/*` → the backend (`SECFORGE_API_PORT`,
default 61021), stripping the `/api` prefix. The backend is optional for the KB view.

No backend is required — the dictionary markdown is imported at build time
(`import.meta.glob`) and rendered client-side. The viewer **reads** the catalog; it never
modifies it (per [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — the topic folders are the
content source).

## What's implemented

- **Knowledge Base view** — collapsible category sidebar (driven by `catalog/INDEX.md`),
  per-page table of contents with scroll-spy, breadcrumb, status badges (complete / draft).
- **Markdown rendering** — `marked` + `highlight.js` with a custom navy/teal code theme;
  external links open in a new tab, relative repo links render as quiet references.
- **Search** — instant client-side filter across title, OWASP alias, summary, and body.
- **Language toggle (EN ⇄ VI)** — switches UI strings and loads the `*.vi.md` content
  variant when present, falling back to English otherwise (see
  [`../docs/SKILLS_AND_I18N.md`](../docs/SKILLS_AND_I18N.md)).

## Design system

Shares the visual identity of `sgu_lookup_tool` (the "LyteNyte" theme): a dark navy-ink
ground (`#060B16`) with a neon-teal accent (`#22B890` / `#40D4A8`), the **Geist** typeface,
sharp corners, hairline borders, and a teal glow rising from the bottom of the page. Status
hues (amber / red) are kept separate from the teal accent. Tokens live in
[`src/index.css`](src/index.css) (`@theme`).

## Structure

```
src/
├── main.jsx              app entry
├── index.css            theme tokens, prose styles, highlight.js theme
├── App.jsx              layout shell, hash routing, locale + search state
├── content/catalog.js   loads + parses the dictionary (Vite glob over ../vuln_search/catalog)
├── lib/markdown.js      marked + highlight.js, TOC extraction, heading anchors
├── i18n/strings.js      UI strings (en / vi)
└── components/          TopNav · Sidebar · Toc · DocView · Landing · Breadcrumb · …
```

## Connects to

- [`../vuln_search/`](../vuln_search/README.md) — the dictionary it renders (content source).
- [`../i18n/`](../i18n/README.md) — UI string lookup and content-language selection.
- [`../backend/`](../backend/README.md) — future tabs (Agent Console, Defense, Labs) will
  fetch JSON from the API; the KB view is self-contained and needs no backend.
