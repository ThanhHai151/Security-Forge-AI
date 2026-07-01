# SecForge — Architecture & Data Flow

The second project-wide overview. [`README.md`](README.md) lists *what* SecForge does;
this file explains *how the pieces fit together*. It is the reference each directory's
README is consistent with.

> Implemented: this describes the design, and the code now follows it. Each pillar has a
> module and tests; the backend exposes them over HTTP and the frontend renders them.

---

## Layered view

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ frontend/  — single-page console; one tab per pillar; EN/VI toggle             │
│   Knowledge Base │ Vuln Search │ Agent Console │ Defense │ Router               │
└───────────────────────────────┬────────────────────────────────────────────────┘
                                 │ HTTP / JSON
┌───────────────────────────────▼────────────────────────────────────────────────┐
│ backend/  — HTTP API + orchestration; serves the UI, mediates every module       │
└───┬─────────────┬──────────────┬───────────────┬────────────────────────────────┘
    │             │              │               │
┌───▼──────┐ ┌────▼───────┐ ┌────▼─────────┐ ┌───▼────────┐
│knowledge_│ │vuln_search │ │ai_framework  │ │defense     │
│base      │ │            │ │(agent+skills+│ │            │
│          │ │            │ │ tools+memory+│ │            │
│          │ │            │ │ research+    │ │            │
│          │ │            │ │ notes+models)│ │            │
└──────────┘ └────────────┘ └──────────────┘ └────────────┘
        ▲                                             ▲
        └──────── i18n/ wraps every user-facing string ┘
```

---

## The pillars, and how they connect

### 1. Knowledge Base (`knowledge_base/` + `frontend/`)
Indexes the repo's `.md` files into searchable documents and renders them as HTML for the
viewer. Provides the **error/troubleshooting search** the brief asks for (a search focused
on the `Troubleshooting_Guide/` notes). Everything else can link into a KB document, so
this pillar is the shared reference surface.

### 2. AI Framework (`ai_framework/`)
The engine. A reasoning **agent** selects relevant **skills** (knowledge) and invokes
**tools** (actions), while **memory**, **research**, and **notes** persist and grow what it
knows. A pluggable **model** backend supplies the reasoning. See the internal flow below.

### 3. Vuln Search (`vuln_search/`)
Answers "what could be wrong here?" from two sources: the indexed knowledge base, and —
when something is new/unknown — an automated CVE lookup. Feeds candidates to the agent.

### 4. Defense (`defense/`)
The same skills/agent/model, pointed *inward*: review a web project for the catalogued
vulnerability classes and produce hardening recommendations or fixes.

### 5. Router (`ai_framework/router/`)
The AI connection pool: many provider accounts (API-key or OAuth sign-in) behind one
rotating backend with quota/ban-aware fallback. Every pillar that reasons — the agent,
Defense review, VI translation — runs on whatever the Router selects.

---

## Inside the AI framework — the loop

The core is an **observe → reason → act → observe** loop with a log-driven planner:

```
 goal + target
      │
      ▼
 [agent] ── loads relevant ──▶ [skills]   (which technique applies? what payloads?)
      │
      ▼
 [model] reasons ──▶ proposes the next action
      │
      ▼
 [tools] run the action ──▶ produce pentest LOGS
      │
      ▼
 [agent] reads the logs ──▶ updates [memory] + [notes]
      │                        │
      │   if KB lacks coverage ▼
      │                     [research] (web / CVE) ──▶ back into memory
      ▼
 LOG-DRIVEN PLANNER: from these logs, generate the next step ──┐
      │                                                         │
      └──────────────────── repeat ◀────────────────────────────┘
```

Component responsibilities:

| Component   | Role                                | Inspired by                        |
|-------------|-------------------------------------|------------------------------------|
| `agent/`    | The loop + the log-driven planner.  | hermes-agent                       |
| `skills/`   | On-demand knowledge; maps each KB topic to a skill manifest. | Anthropic-Cybersecurity-Skills |
| `tools/`    | Categorised, runnable actions.      | hackingtool                        |
| `memory/`   | Persistent facts across sessions.   | hermes-agent                       |
| `headroom/` | Context-window budgeting & compaction in front of the backend. | — |
| `research/` | Fills knowledge gaps autonomously.  | —                                  |
| `notes/`    | Structured, reviewable findings.    | —                                  |
| `models/`   | Pluggable LLM backend (Claude / offline). | —                            |

**Log-driven planning** is the capability called out in the brief: the planner consumes
the logs produced by the just-finished step and emits the next execution plan, rather than
following a fixed script. This is what makes the framework *adaptive*.

---

## Offense and defense share one core

`defense/` is not a separate engine. It reuses the same `agent/`, `skills/`, and `models/`
as the pentest framework, but inverts the objective: instead of "find a way in," it asks
"where could someone get in, and how do we close it?" The skills already encode both the
attack and the secure-implementation guidance (the KB notes contain "Secure
Implementation" and "Defense Checklist" sections), so one knowledge base serves both
directions.

---

## Multi-language architecture (`i18n/`)

Two layers are localized independently:

- **UI strings** — keyed locale files (`en`, `vi`); the frontend swaps them instantly on
  toggle, no reload.
- **Content** — the knowledge notes and agent output. English is the canonical source.
  Vietnamese is served from cached translations when available, or generated on demand via
  the `models/` backend and then cached.

The contract: nothing user-facing is hard-coded in a single language. Strings go through a
lookup; content carries a language tag so the viewer can request the variant it needs.

---

## Cross-cutting concerns

- **Configuration** — one source of truth for the KB root path, ports, the chosen model
  backend, and feature flags. Lives with the backend.
- **Secrets** — never in files; model API keys come from an environment variable or the
  account store (OAuth tokens included), and the API layer masks them.
- **Safety** — every network action (built-in HTTP, the `run_recon` external-CLI runner, the
  headless browser) passes through the one `require_authorized[_host]` scope gate; intrusive
  scans and state-changing calls are held for operator approval; findings are replayed by a
  verifier before they're trusted; and Defense findings are proposals, not automatic changes.
- **Extensibility = add a file.** New skill → a skill manifest in `skills/`. New tool →
  an entry in `tools/`. New provider → a preset in `backend/providers.py`. The platform
  discovers them.
