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
  matching skills, and renders a briefing for an external coding agent to execute; results
  are recorded back into a per-domain notebook (confirmed / unconfirmed / untested). Scan
  modes `quick` / `standard` / `deep` control how much ground it covers. SecForge itself
  never calls an AI provider or touches the target — it only advises. (`ai_framework/supervisor/`)
- **Defense** — point it at a codebase to review source for known vulnerability classes and
  scan dependencies for CVEs. (`defense/`)
- **Vuln search** — search the knowledge base and pull in public CVEs for unfamiliar errors
  or technologies. (`vuln_search/`)
- **Reporting** — export a domain's findings as SARIF 2.1.0 for CI / code-scanning upload.
- **Bilingual** — the UI and displayed content switch between English and Vietnamese.

Full architecture and data flow: [`ARCHITECTURE.md`](ARCHITECTURE.md). See
[`docs/STRIX_PARITY_PLAN.md`](docs/STRIX_PARITY_PLAN.md) for the current roadmap.

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
