# SecForge

**SecForge** is a local, agentic security-research platform. It turns a large corpus of
web-security notes into a fast, searchable web app, and pairs it with an AI framework that
can drive a penetration test, defend a codebase, and research new vulnerabilities — end to
end, on your own machine.

> **Status:** implemented and tested. All eight pillars ship working code and tests
> (`pytest` green, `ruff` + `mypy` clean, the frontend builds).
>
> **Authorized use only.** SecForge is for security research, CTFs, and testing systems you
> own or are explicitly authorized to assess. The agent enforces an allow-listed target gate;
> keep it that way.

This file and [`ARCHITECTURE.md`](ARCHITECTURE.md) are the two project-wide overviews. Every
other `README.md` is scoped to the directory it lives in.

---

## Features

| # | Feature | Directory |
|---|---------|-----------|
| 1 | **Notion-like knowledge viewer** — renders ~278 markdown notes with collapsible category nav, per-page table of contents, syntax-highlighted payloads, and full-text search. | [`frontend/`](frontend/README.md), [`knowledge_base/`](knowledge_base/README.md) |
| 2 | **AI pentest framework** — an agent that runs a test the way a human would: pick a technique, run a tool, read the result, decide the next move. | [`ai_framework/`](ai_framework/README.md) |
| 3 | **Log-driven planning** — feed each step's logs back in and the agent produces the next execution plan, closing the observe → reason → act loop. | [`ai_framework/agent/`](ai_framework/agent/README.md) |
| 4 | **Defensive review** — point SecForge at a web codebase and it reviews for the catalogued vulnerability classes, then recommends concrete hardening. | [`defense/`](defense/README.md) |
| 5 | **Two-way vuln discovery** — search the indexed knowledge base, and auto-search public CVE sources when an unfamiliar error/technology appears. | [`vuln_search/`](vuln_search/README.md) |
| 6 | **Persistent memory (Hermes-style)** — findings, target facts, and lessons persist across steps and sessions. | [`ai_framework/memory/`](ai_framework/memory/README.md) |
| 7 | **Self-research** — when the KB falls short, the agent researches (web + CVE) and folds the result back into its working knowledge. | [`ai_framework/research/`](ai_framework/research/README.md) |
| 8 | **Structured note-taking** — captures findings, working payloads, and to-dos; reviewable in the UI and reusable by the agent. | [`ai_framework/notes/`](ai_framework/notes/README.md) |
| 9 | **Sandboxed labs** — opt-in, PortSwigger-style practice targets. | [`labs/`](labs/README.md) |
| 10 | **Red-team OPSEC reference** — stealth/evasion tradecraft paired with its blue-team detection counterpart. | [`docs/RED_TEAM_OPSEC.md`](docs/RED_TEAM_OPSEC.md) |
| 11 | **Bilingual (EN ⇄ VI)** — UI strings and displayed content switch between English and Vietnamese. | [`i18n/`](i18n/README.md) |

---

## Quick start

**Prerequisites:** Python **3.11+**, Node.js **18+** (npm), and `make` (optional — the raw
commands are shown alongside each target).

### 1. Install

```bash
make install          # pip install -e ".[dev]"
```

### 2. Run the app (web UI + backend API)

```bash
cd frontend
npm install
npm run dev:all       # starts Vite (web) and the Python API together
```

- Web UI: served by Vite (see the printed local URL, e.g. `http://127.0.0.1:5173`).
- Backend API: `python -m backend.app` (run standalone via `npm run dev:backend`).

### 3. Try the agent (offline, no API key)

```bash
make demo             # python -m ai_framework.demo --goal "Recon the target" \
                      #   --target http://localhost:8000 --backend offline
```

### 4. Optional: sandboxed labs

```bash
make labs             # SECFORGE_LABS_ENABLED=1 python -m labs.server
```

---

## Testing & quality

```bash
make test             # pytest — offline, no API key needed
make lint             # ruff check + mypy across all packages
```

| Pillar | Code | Backend route | Tests |
|--------|------|---------------|-------|
| Knowledge base | [`knowledge_base/`](knowledge_base/README.md) | `/kb`, `/kb/doc/{id}`, `/kb/search` | `tests/test_knowledge_base.py` |
| Vuln search | [`vuln_search/`](vuln_search/README.md) | `/vuln-search` | `tests/test_vuln_search.py` |
| Defense | [`defense/`](defense/README.md) | `/defense/review` | `tests/test_defense.py` |
| Labs | [`labs/`](labs/README.md) | `/labs` (+ opt-in server) | `tests/test_labs.py` |
| i18n | [`i18n/`](i18n/README.md) | `/i18n/{locale}` | `tests/test_i18n.py` |
| AI framework | [`ai_framework/`](ai_framework/README.md) | `/runs`, `/memory`, `/accounts` | `tests/test_*` |

---

## Architecture

SecForge is organized as pillars behind a single HTTP backend that serves the frontend and
drives the agent modules. Full data flow lives in [`ARCHITECTURE.md`](ARCHITECTURE.md).

```
secforge/
├── README.md            ← overview #1 — features & how to run (this file)
├── ARCHITECTURE.md      ← overview #2 — structure & data flow
├── frontend/            Web viewer UI (React + Vite) + EN/VI language toggle
├── backend/             HTTP API & orchestration serving the UI and modules
├── knowledge_base/      Index & render the .md notes, error/full-text search
├── ai_framework/        The AI pentest framework (umbrella)
│   ├── agent/           reasoning loop + log-driven next-step planner
│   ├── skills/          on-demand security knowledge (skill manifests)
│   ├── tools/           runnable tool catalog (recon, http, injection, …)
│   ├── memory/          persistent, cross-session memory
│   ├── research/        self-research (web + CVE)
│   ├── notes/           structured note-taking
│   └── models/          pluggable LLM backends (Claude, offline)
├── vuln_search/         Find vulns from docs + auto-CVE on new errors
├── defense/             Review / harden any web project (defensive)
├── labs/                Sandboxed practice targets (PortSwigger-style)
├── i18n/                EN/VI localization (cross-cutting)
└── docs/                Deeper design notes & specifications
```

---

## Tech stack

| Layer | Languages / tools |
|-------|-------------------|
| **Frontend** | React + Vite, TypeScript, Tailwind CSS |
| **Backend & agent** | Python 3.11+ (primary); Rust for performance-critical hot paths |
| **Data & config** | SQL, YAML / TOML / JSON, Dockerfile, Bash |

The AI framework is Python-first (the ecosystem for agent/LLM/MCP work); Rust is reserved for
hot paths such as fast tool runners and token counting. Pluggable model backends are defined
in [`ai_framework/models/`](ai_framework/models/README.md), including an **offline** backend
so tests and the demo run without an API key.

---

## Multi-language

Localization is a first-class concern, split cleanly into two layers:

- **Documentation is English-only** — one canonical source of truth for every `.md`.
- **The product switches EN ⇄ VI at runtime:**
  - **UI strings** (menus, buttons, labels) come from locale files and switch instantly.
  - **Displayed content** (knowledge notes, agent output) is English at the source;
    Vietnamese is served from stored translations or produced on demand by the model.

Content and presentation language stay separated so a toggle can re-render without a reload.
Details in [`i18n/`](i18n/README.md).

---

## Inspirations

| Reference project | What SecForge borrows | Directory |
|-------------------|-----------------------|-----------|
| **Anthropic Cybersecurity Skills** | "Skills" — structured, on-demand security knowledge. | [`ai_framework/skills/`](ai_framework/skills/README.md) |
| **NousResearch / hermes-agent** | The reasoning loop + persistent memory. | [`ai_framework/agent/`](ai_framework/agent/README.md), [`memory/`](ai_framework/memory/README.md) |
| **Z4nzu / hackingtool** | A categorized catalog of runnable tools. | [`ai_framework/tools/`](ai_framework/tools/README.md) |

Practice targets follow the **PortSwigger Web Security Academy** model — see
[`labs/`](labs/README.md).
