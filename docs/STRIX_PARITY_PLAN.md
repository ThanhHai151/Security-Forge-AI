# Strix-parity plan for SecForge (sf_agent)

Goal: bring SecForge to feature parity with the reference tool **Strix**
(`../Tool/strix`, an autonomous AI pentester) **without abandoning SecForge's deliberate
"Expert Supervisor" architecture** — i.e. make SecForge *advise an external coding agent
(Claude Code) as well as Strix executes autonomously*, rather than rebuilding SecForge into a
Strix clone.

> Direction note (2026-07-08): the request "add what's missing, like the reference tool"
> forks into (A) **advisory parity** — port Strix's knowledge/methodology/reporting into the
> supervisor, keeping SecForge advisory; or (B) **autonomous parity** — re-enable/rebuild the
> gated Hermes engine + a Docker sandbox. We proceeded with **(A)**: it respects the
> documented 2026-07-03 pivot away from autonomy, is the highest-value/lowest-risk reading,
> and does not duplicate the already-gated autonomous engine. Switching to (B)/both is a
> separate decision — see "Explicitly out of scope" below.

---

## 1. How the reference tool (Strix) works — root cause

Strix is an autonomous multi-agent AI pentester. The engine is four layers:

1. **Brain** — the `openai-agents` SDK + LiteLLM drive a streaming loop (`Runner.run_streamed`),
   provider-agnostic via `StrixProvider(MultiProvider)`.
2. **Hands** — each agent is a `SandboxAgent`; its Shell/Filesystem tools run **inside a Docker
   Kali sandbox** baked with the full toolkit (nmap, nuclei, ffuf, sqlmap, Caido proxy,
   Playwright browser, semgrep, …). URL/IP targets are reached over a Caido proxy; repos/dirs
   are copied or bind-mounted into `/workspace`.
3. **Coordination** — an `AgentCoordinator` owns a parent→child agent graph (statuses,
   inter-agent messages, budget/rate-limit stops, JSON+SQLite resume).
4. **Knowledge** — ~51 markdown **skills** injected into the system prompt (statically at spawn +
   on-demand via `load_skill`), plus a prescriptive system prompt encoding the methodology.

**Workflow doctrine:** recon/mapping → spawn one specialist subagent per *(vuln type ×
component)* → Discovery → Validation (working PoC) → Reporting (`create_vulnerability_report`,
CVSS3 + LLM-dedup) → Fixing (white-box, edit source + re-test + diff). Lifecycle is enforced:
every turn is a tool call; runs end only via `finish_scan`/`agent_finish`.

**Outputs:** `strix_runs/<name>/` — `penetration_test_report.md`, per-vuln markdown,
`vulnerabilities.{json,csv}`, **`findings.sarif` (SARIF 2.1.0 + STRIDE + fingerprints + fixes)**,
`run.json`, cost/token ledger. **Modes:** quick/standard/deep; scope full/diff/auto (CI PR
diff-scoping). **Interfaces:** Textual TUI + `-n` headless (exit 2 if vulns found) for CI.

## 2. How SecForge works — and the gaps

SecForge pivoted to the **Expert Supervisor**: deterministic, **no LLM calls, no target
execution**. `advise()` ranks taxonomy techniques (keyword + notebook status + archetype),
selects skills, and renders a Markdown `context_block` briefing for an external agent to
execute. Findings return by pasting the agent's raw output into `/notebook/{domain}/ingest`
(verbatim store + marker parse). The old autonomous Hermes engine is **gated off**
(`SECFORGE_ENABLE_AUTONOMOUS=1`).

| Area | Strix | SecForge before | Plan |
|---|---|---|---|
| Skills | ~51 (vuln + frameworks/protocols/tech/cloud/tooling) | 14 (11 exploit + 3 opsec) | **Phase 1** expand |
| Scan modes | quick/standard/deep | none | **Phase 2 ✅ done** |
| Methodology doctrine | per-vuln agent chains | plan steps only | **Phase 3 ✅ done** |
| Reporting | SARIF+STRIDE+CVSS+dedup | findings MD/JSON | **Phase 4 ✅ backend done** |
| Live agent bridge | owns the LLM loop | manual paste mirror | **Phase 5** (needs sign-off) |
| CI | `-n` + SARIF upload | none | **Phase 6** |

## 3. Phased plan

### Phase 2 — Scan modes ✅ DONE (this session)
- `SessionContext.scan_mode` (`quick|standard|deep`, default `standard`).
- `strategy.SCAN_MODE_STEP_BUDGET` (3/6/8), `HIGH_IMPACT_NODES` bias for quick, `resolve_scan_mode`.
- Briefing renders a per-mode **posture** paragraph.
- Backend: `POST /supervisor/advise` accepts `scan_mode`; `RunService.advise(scan_mode=…)`.
- Tests: `tests/test_scan_modes.py` (9).

### Phase 3 — Methodology / coordination doctrine ✅ DONE (this session)
- Briefing renders a **"## Methodology — run this loop per technique"** section adapted from
  Strix's Discovery→Validation→Reporting(→Fixing) chain, expressed for a single coding agent;
  Fix step only in whitebox; explicit vuln-chaining guidance; one-thread-per-(technique×component).
- Tests: covered in `tests/test_scan_modes.py`.

### Phase 4 — Reporting parity (SARIF) ✅ backend DONE (this session)
- `ai_framework/report/sarif.py::notebook_to_sarif` — confirmed/unconfirmed notebook nodes →
  SARIF 2.1.0 results; per-technique rules with CWE helpUri (via `vuln_search.mapping`),
  OWASP/ATT&CK/WSTG + **STRIDE** tags, coarse class-inherent `security-severity`, stable
  `partialFingerprints`, DAST `logicalLocations`. `untested` excluded; empty notebook → valid
  empty run (auto-resolves stale alerts, like Strix).
- Backend: `GET /notebook/{domain}/sarif`; `RunService.notebook_sarif`.
- Tests: `tests/test_sarif.py` (6).
- **Remaining:** frontend "Download SARIF" button (Phase 6); optional per-finding CVSS input so
  severity is per-instance instead of class-heuristic.

### Phase 1 — Skills library expansion (PENDING)
Port/adapt Strix's missing skills into `ai_framework/skills/<name>/SKILL.md` (Apache-2.0, adapt
+ attribute), and extend `strategy.SKILL_TAXONOMY_MAP`. Priority order:
1. Missing **vuln** classes already in the taxonomy but with no skill: `csrf`, `xxe`(have),
   `path_traversal`, `open_redirect`, `race_condition`, `information_disclosure`,
   `insecure_deserialization`(have), `prototype_pollution`, `mass_assignment`,
   `business_logic`, `broken_access_control` depth. (Map each to its taxonomy slug.)
2. **Protocol/framework/tech** skills: `graphql`, `oauth`, `django`/`fastapi`/`nextjs`,
   `supabase`/`firebase`. (These become *catalog-only* until a taxonomy node exists.)
3. **Tooling** playbooks: `nmap`, `nuclei`, `ffuf`, `sqlmap`, `httpx`, `katana`, `semgrep` —
   condensed CLI cheat-sheets for the external agent.
Each skill: keep SecForge's frontmatter (`name`, `description`, `tags`, `domain`, `subdomain`,
`owasp`) + `## When to Use` trigger. Test: registry discovers it, `SKILL_TAXONOMY_MAP` resolves,
`advise()` surfaces it for the matching question.

### Phase 5 — Live Claude Code bridge (PENDING — needs sign-off)
The SupervisorPanel "Terminal" is a manual copy-paste mirror today. Replace with a real bridge
so the loop is closed automatically. **Two candidate mechanisms (pick one):**
- **(a) Spawn** `claude -p "<context_block>\n<question>" --output-format stream-json` as a
  subprocess, stream events into the UI, auto-run `ingest` on the final text.
- **(b) Tail** Claude Code's own persisted session JSONL transcript (read-only; no process
  control) and ingest markers as they appear.
Recommendation: (b) is lower-risk (no process spawning), (a) is more automated.
**This is outward-facing / hard-to-reverse (spawns or reads external processes/files), so it
needs explicit confirmation on the mechanism before implementation.** New module
`ai_framework/bridge/`, backend SSE route, SupervisorPanel wiring. Tests: parse a canned
stream-json / JSONL fixture into ingest markers (no live process in CI).

### Phase 6 — Frontend + CI (PENDING)
- SupervisorPanel: scan-mode selector (quick/standard/deep) wired into the `advise` body;
  "Download SARIF" button hitting `GET /notebook/{domain}/sarif`.
- `frontend/src/lib/api.js`: add `scan_mode` to `advise`, add `notebookSarif(domain)`.
- Docs: a GitHub Actions recipe that posts the SARIF to code-scanning (mirrors Strix's CI).
- Verify with `npm run build`.

## 4. Test strategy (mirrors the reference tool)
Strix tests only its **deterministic scaffolding** (config, cost, SARIF, CLI parsing) — never
the live LLM loop (needs keys+Docker). SecForge is *entirely* deterministic, so everything is
unit-testable offline. Gate for every phase: `pytest` + `ruff check <pkgs> tests` +
`mypy <pkgs>` (see `Makefile`). Note: 3 pre-existing `anthropic_backend.py` mypy errors are
CI-invisible — leave them (see `docs`/memory).

## 5. Explicitly out of scope (respecting the pivot)
- Turning SecForge into an autonomous executor, re-enabling the gated Hermes engine by default,
  or adding a Docker sandbox + baked pentest toolkit. SecForge delegates execution to Claude
  Code by design. Revisit only if the direction changes to (B)/both.
