# SecForge

**SecForge** is a local, agentic security-research platform: a searchable knowledge base of
web-vuln classes, a defensive code/dependency reviewer, and an **Expert Supervisor** that
plans a pentest and hands the strategy to a coding agent (e.g. Claude Code) to carry out.

> **Authorized use only.** SecForge is for security research, CTFs, and testing systems you
> own or are explicitly authorized to assess.

---

## Guide

- **Knowledge base** — browse ~278 markdown security notes with search, table of contents,
  and syntax-highlighted payloads. (`knowledge_base/`)
- **Expert Supervisor** — give it a domain + question, it ranks the right techniques, picks
  matching skills, classifies the application archetype, and generates an evidence-led chain
  of logical questions for an external coding agent to resolve. Its vendor-neutral red-team
  harness freezes a typed Rules of Engagement, fails closed on missing authorization/scope/time,
  and renders native guidance for Claude Code, Codex, or Cursor. Each of the 29 vulnerability
  catalog entries has its own skill, so branches such as JWT `alg:"none"`, social-network
  upload/race checks, and database-specific SQLi probes are loaded only when relevant. Results
  are recorded back into a per-domain notebook (confirmed / unconfirmed / untested). Scan modes
  `quick` / `standard` / `deep` control breadth and question depth. SecForge itself never calls
  an AI provider or touches the target — it only advises. (`ai_framework/supervisor/`,
  `ai_framework/harness/`)
- **Defense** — point it at a codebase to review source for known vulnerability classes and
  scan dependencies for CVEs. (`defense/`)
- **Vuln search** — search the knowledge base and pull in public CVEs for unfamiliar errors
  or technologies. (`vuln_search/`)
- **Reporting** — export a domain's findings as SARIF 2.1.0 for CI / code-scanning upload.
- **Bilingual** — the UI and displayed content switch between English and Vietnamese.

Full architecture and data flow: [`ARCHITECTURE.md`](ARCHITECTURE.md). Harness design and
enforcement boundary: [`docs/RED_TEAM_AGENT_HARNESS.md`](docs/RED_TEAM_AGENT_HARNESS.md).

---

## Install

**Prerequisites:** Python 3.11+, Git, and Node.js 18+ (for the Web UI). The installer checks
for and auto-installs what it can.

```bash
git clone https://github.com/ThanhHai151/Security-Forge-AI.git
cd Security-Forge-AI
```

**Linux / macOS / WSL2:**

```bash
bash install.sh
```

**Windows (PowerShell):**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # if scripts are blocked
.\install.ps1
```

**Run it** (open a new terminal first, so the updated PATH is picked up):

```bash
secforge            # interactive menu: 1) Web UI  2) Terminal UI  3) Serve only
```

The Web UI opens at **http://localhost:61022**. Non-interactive options: `secforge web`,
`secforge tui`, `secforge serve`. Re-run the installer any time to update in place.

### Run from source (developers)

```bash
pip install -e ".[dev]"     # or: make install
cd frontend && npm install
npm run dev:all             # Vite (web, :61020) + the Python API (:61021) together
```

```bash
make test    # pytest — offline, no API key needed
make lint    # ruff check + mypy across all packages
```

Copy `.env.example` to `.env` to pick a model backend (default `offline`, no key needed).
