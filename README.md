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
| 9 | **Real external tooling** — a scope-gated `run_recon` runs allow-listed CLIs (httpx, nuclei, ffuf, nmap, subfinder…); every host is authorized-gated, intrusive scans held for approval. | [`ai_framework/tools/external.py`](ai_framework/tools/external.py) |
| 10 | **Authenticated sessions + OPSEC transport** — a per-run cookie jar (`login`/`set_auth`, auto-CSRF) so authenticated bugs are reachable, routed through an optional proxy + custom User-Agent. | [`ai_framework/tools/session.py`](ai_framework/tools/session.py) |
| 11 | **JWT attack kit** — `jwt_attack`: alg-none forge, HS256 secret cracking, and token forging, all local/stdlib. | [`ai_framework/tools/jwt.py`](ai_framework/tools/jwt.py) |
| 12 | **Verified findings** — a finding carries a `repro` that SecForge replays; the report marks each ✅ verified or ⚠️ unverified, killing false positives. | [`ai_framework/agent/verify.py`](ai_framework/agent/verify.py) |
| 13 | **Recon asset graph + framework mapping** — discovered endpoints/params/tech tracked as structure; every class mapped to CWE · OWASP · ATT&CK · WSTG. | [`ai_framework/agent/assets.py`](ai_framework/agent/assets.py), [`vuln_search/mapping.py`](vuln_search/mapping.py) |
| 14 | **Red-team OPSEC reference** — stealth/evasion tradecraft paired with its blue-team detection counterpart. | [`docs/RED_TEAM_OPSEC.md`](docs/RED_TEAM_OPSEC.md) |
| 15 | **Bilingual (EN ⇄ VI)** — UI strings and displayed content switch between English and Vietnamese. | [`i18n/`](i18n/README.md) |

---

## Install & run

One installer sets everything up: it creates an isolated Python environment, builds the
Web UI, and puts a **`secforge`** command on your PATH. Then you just run `secforge`.

**Prerequisites:** the installer checks for and (where possible) auto-installs these, but
you can also install them yourself first — **Python 3.11+**, **Git**, and **Node.js 18+**
(npm, only needed for the Web UI).

```bash
git clone https://github.com/ThanhHai151/Security-Forge-AI.git
cd Security-Forge-AI
```

### 🐧 Linux &nbsp;/&nbsp; 🍎 macOS &nbsp;/&nbsp; WSL2

```bash
bash install.sh
```

### 🪟 Windows (PowerShell)

```powershell
# If scripts are blocked, allow this session first:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

### Start it

Open a **new terminal** (so the updated PATH is picked up), then:

```bash
secforge            # interactive menu: 1) Web UI  2) Terminal UI  3) Serve only
```

The Web UI opens in your browser at **http://localhost:61022**. Non-interactive commands
are available too: `secforge web` (serve + open browser), `secforge tui` (terminal UI),
`secforge serve` (serve only). Re-running the installer updates SecForge in place.

---

## Run from source (developers)

Prefer live-reload while hacking on the code? Skip the installer and run the two dev
servers directly (Vite on **:61020**, backend API on **:61021**):

```bash
pip install -e ".[dev]"     # or: make install
cd frontend && npm install
npm run dev:all             # starts Vite (web) + the Python API together
```

Try the agent offline (no API key needed):

```bash
make demo    # python -m ai_framework.demo --goal "Recon the target" --target http://localhost:8000 --backend offline
```

> **Configuration:** copy `.env.example` to `.env` to pick a model backend. The default is
> `offline` (heuristic, no key) so everything runs out of the box; set `anthropic` or
> `openrouter` and add a key for live LLM calls.

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
