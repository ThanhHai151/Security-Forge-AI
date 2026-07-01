# External Toolkits — Integration Design

> **What:** how three real, locally-vendored upstream repositories fold into SecForge's
> existing pillars — the concrete realization of the inspirations already named in
> [`../ARCHITECTURE.md`](../ARCHITECTURE.md) and [`SKILLS_AND_I18N.md`](SKILLS_AND_I18N.md).
>
> **Where they live (not vendored into this repo):**
> - `/home/thanhhai/Documents/TOOL/hackingtool` — Z4nzu **hackingtool**
> - `/home/thanhhai/Documents/TOOL/Anthropic-Cybersecurity-Skills` — mukul975
> - `/home/thanhhai/Documents/TOOL/Claude-BugHunter`
>
> **Design principle:** each toolkit maps onto an *existing* SecForge pillar. No new engine,
> no new top-level directory — **extensibility = add a file** (per
> [`../ARCHITECTURE.md` › Cross-cutting](../ARCHITECTURE.md#cross-cutting-concerns)). All three
> *reinforce* the authorized-target gate + OPSEC posture; none bypass it.

---

## 0. The three at a glance

| Toolkit | What it is | Scale | Maps onto |
|---------|-----------|-------|-----------|
| **hackingtool** | Menu/catalog of runnable pentest tools with install/run commands per tool | 160 tools · 20 categories | [`ai_framework/tools/`](../ai_framework/tools/README.md) |
| **Anthropic-Cybersecurity-Skills** | agentskills.io `SKILL.md` library, framework-mapped (MITRE/NIST) | 817 skills · 29 domains | [`ai_framework/skills/`](../ai_framework/skills/README.md) |
| **Claude-BugHunter** | Bug-bounty / red-team **methodology**: engagement lifecycle, validation gates, reporting | 71 hunt skills · 15 commands · deterministic engine | [`agent/`](../ai_framework/agent/README.md) + [`notes/`](../ai_framework/notes/README.md) + [`defense/`](../defense/README.md) |

The three are complementary, not overlapping: **skills** are *what the agent knows*, the **tool
catalog** is *what it can run*, and the **methodology** is *how a run is structured, validated, and
reported*.

---

## 1. Anthropic-Cybersecurity-Skills → `skills/`  (highest value — do first)

### Why first
It is the same `SKILL.md` format SecForge already adopted (see
[`SKILLS_AND_I18N.md` §2](SKILLS_AND_I18N.md)), so it is close to a drop-in and is the single
largest knowledge upgrade: 817 skills across 29 domains vs. SecForge's current starter set.

### What to adopt
1. **Extend the skill frontmatter** with the framework-mapping fields the upstream uses, kept
   optional and additive to SecForge's existing fields (`languages`, `catalog`, `deep_dive`):
   ```yaml
   mitre_attack: [T1190, T1059.001]     # ATT&CK technique IDs
   nist_csf: [DE.CM-01, RS.AN-03]       # NIST CSF 2.0 subcategories
   d3fend_techniques: [D3-NTA]          # defensive counterparts (feeds defense/)
   atlas_techniques: [AML.T0047]        # AI/ML threats (feeds web_llm_attacks)
   ```
2. **Generate a `skills/index.json`** — one lightweight record per skill
   (`name`, `description`, `domain`, `subdomain`, `tags`, `path`, ~30 tokens each). This is the
   **progressive-disclosure** contract: the agent scans the index cheaply, then loads only the
   top-N full `SKILL.md` bodies it selects. This is exactly what Headroom needs to keep skill
   loading inside budget (see [`INTEGRATION_PLAN.md` §3](INTEGRATION_PLAN.md)).
3. **Framework-ID query** in skill discovery — let the loop (and Vuln Search) ask "which skills
   map to `T1003`?" or "which cover NIST `DE.CM-01`?", not just keyword match.
4. **Defense counterpart wiring** — `d3fend_techniques` on a skill gives
   [`defense/`](../defense/README.md) the defensive mapping for the same class it attacks,
   consistent with "offense and defense share one core".

### Boundaries
Import selectively into the EN/VI corpus; each imported skill still needs a `SKILL.vi.md` to
satisfy the i18n rule. Keep `author`/`license` attribution (Apache-2.0) intact.

---

## 2. hackingtool → `tools/`  (a *catalog*, not an auto-runner)

### The shape it provides
Every hackingtool entry is trivially serializable to a catalog record:
```json
{
  "title": "Nuclei", "description": "Template-based vulnerability scanner",
  "install_commands": ["go install .../nuclei@latest"],
  "run_commands": ["nuclei -u <target> -t <template>"],
  "project_url": "https://github.com/projectdiscovery/nuclei",
  "supported_os": ["linux", "macos"], "tags": ["web", "scanner"],
  "requires": {"root": false, "docker": false, "go": true}, "category": "web_attack"
}
```
Its 20 categories map onto the tool categories SecForge already planned
([`tools/README.md`](../ai_framework/tools/README.md)): recon (`information_gathering`), http/web
(`web_attack`), injection (`sql_injection`, `xss_attack`), auth/AD (`active_directory`),
decode/encode (local), plus cloud, forensics, wireless, mobile, RE.

### The rule that keeps it safe
Ingest hackingtool as **read-only catalog metadata the agent consults for recommendations**
("for this step, `wafw00f` fingerprints the WAF"). **Do not auto-execute catalog entries.** Many
categories are destructive or noisy (`ddos`, `phishing_attack`, `post_exploitation` C2 like
Sliver/Havoc/Mythic). Actual execution stays behind the existing gates:
- `require_authorized` (localhost or an explicitly authorized target),
- OPSEC pacing for `touches_network` tools,
- the tighter guardrail leash on `mutating` tools.

So the catalog *expands what the agent can suggest and reason about*; it does not expand what runs
unattended. Wrapping a specific catalog tool as an actually-runnable SecForge `Tool` is a
deliberate, per-tool decision — add a class in `tools/security.py` and register it.

---

## 3. Claude-BugHunter → `agent/` + `notes/` + `defense/`  (the methodology layer)

Claude-BugHunter's value is not more tools or skills — it is **discipline**: how to structure,
validate, and report a run. These map onto the loop and the notes/report pillars.

1. **6-phase engagement lifecycle** — Scope → Recon → Hunt → Validate → Capture → Report.
   Frame the [`agent/`](../ai_framework/agent/README.md) loop's log-driven planner around these
   phases so a run is legible and resumable.
2. **Deterministic-first orchestration** — do breadth deterministically and for free
   (scope check, recon, ranking, mapping endpoints→skills); spend the model only on judgment
   calls (hunt, validate). Cheaper and more predictable than "let the model drive everything",
   and it dovetails with Headroom's budgeting.
3. **The 7-Question validation Gate** — a separate, *adversarial* verifier step that vets every
   candidate finding before it becomes a report entry: demonstrable now? in-scope? impact beyond
   "200 OK"? not on the never-submit list? One NO → KILL; output is
   `PASS / KILL / DOWNGRADE / CHAIN-REQUIRED`. This sits between `note_finding` and the report,
   and the verifier must be a distinct role from the agent that produced the finding.
4. **Mode-confirmation gate** — declare engagement type up front (bug-bounty = impact-only vs.
   red-team = hygiene + IoCs deliverable vs. WAPT vs. audit); it changes what counts as a finding
   and the report shape.
5. **evidence-hygiene + platform-aware reporting** — PII/cookie redaction rules and per-platform
   templates (CVSS/VRT) belong in [`notes/report.py`](../ai_framework/notes/report.py).
6. **Eval harness** — the skills-on vs. skills-off ablation (against a sandboxed target of your
   choice) is how SecForge proves its skills actually raise solve-rate; worth mirroring as a
   `tests/`- or `eval/`-level harness.

### Scope alignment
Claude-BugHunter deliberately excludes internal-AD, post-exploitation, and C2 (external-only
model). That boundary matches SecForge's safety posture — adopt the methodology without importing
the excluded offensive tradecraft.

---

## 4. Suggested order of work

| Step | Deliverable | Rationale |
|------|-------------|-----------|
| 1 | Extend skill frontmatter (framework fields) + generate `skills/index.json` | Unlocks progressive-disclosure discovery; additive, low-risk |
| 2 | Import a first tranche of Anthropic skills (with `SKILL.vi.md`) into the corpus | Biggest knowledge gain |
| 3 | Add framework-ID query to skill/vuln search | Threat-informed recall |
| 4 | Generate the hackingtool JSON catalog (read-only) + a `recommend_tool` lookup | Recommendations without new execution surface |
| 5 | Add the 7-Question validation Gate as an adversarial step before report | Kills weak/OOS findings early |
| 6 | Fold evidence-hygiene + platform templates into `notes/report.py` | Report quality |
| 7 | Stand up the skills-on/off eval harness against a sandboxed target | Proves the skills help |

---

## 5. Safety recap

Everything above is **knowledge and metadata** by default. Skills describe procedures; the tool
catalog describes tools; the methodology describes structure. The only thing that touches a real
target is a registered SecForge `Tool`, and every one of those goes through
`require_authorized` + OPSEC pacing + the mutating leash — unchanged by this integration.

**Status:** design note. Nothing here is implemented yet; it records the intended integration so
the work can proceed file-by-file.
