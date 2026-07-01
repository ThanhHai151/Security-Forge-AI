# Knowledge Base — web-security technique corpus

> **What:** a curated, PortSwigger/OWASP-style reference covering the modern web-attack
> surface, used as SecForge's **skill / knowledge source** — the material the agent recalls
> from and reasons over during an authorized run.
>
> **Where:** `../Troubleshooting_Guide/` (sibling of this repo, **not** vendored in). 32
> technique files + a methodology index and a payload reference; ~61k lines, ~1.9 MB.
> Authored for **authorized testing only**; partly bilingual (English + Vietnamese), which
> ties into the planned `i18n/` layer.

This document explains what the corpus contains and **how it maps onto SecForge's
architecture** so the agent loop, memory, and skills can consume it. The wiring described in
[§3](#3-how-it-feeds-the-agent) is a **design** — it is not implemented yet.

---

## 1. What's in it

Each file is one vulnerability class: a decision tree ("how do I know I'm looking at this?"),
detection steps, exploitation techniques, payloads, and defensive notes.

| Group | Files |
|-------|-------|
| **Injection** | `sql_injection.md`, `nosql.md`, `os_comand.md`, `ssti.md`, `xxe.md`, `path_traversal.md` |
| **Client-side** | `xss.md`, `dom.md`, `csrf.md`, `clickjacking.md`, `cors.md`, `prototype_pollution.md` |
| **Auth & identity** | `authentication.md` (largest, ~14k lines), `jwt.md`, `oauth.md`, `access_control.md` |
| **Server-side / infra** | `ssrf.md`, `http_host_header_attacks.md`, `http_request_smuggling.md`, `web_cache_deception.md`, `web_chace_poisoning.md` |
| **APIs & modern** | `api_testing.md`, `graphql_api.md`, `webshotket.md` (WebSockets), `web_llm_attacks.md` (LLM/prompt-injection) |
| **Other** | `file_upload_bsv.md`, `race_condition.md`, `information_disclosure.md`, `recon.md`, `se_de.md` (serialization) |
| **Cross-cutting indexes** | `skill.md` (methodology / skill index), `payload.md` (consolidated payloads), `README.md` (topic index + decision tree) |

The `README.md` is a routing front-door: a symptom/observation → technique decision tree. That
structure is the most directly reusable part for an automated agent (see §3.2).

---

## 2. Why it matters here

SecForge's agent loop is deliberately empty of domain knowledge — the
[backend](../ai_framework/models/README.md) supplies reasoning, the
[`memory/`](../ai_framework/memory/README.md) layer supplies what *this run* learned, but
neither supplies **what good looks like for each vulnerability class**. This corpus is that
missing third input: durable, human-curated technique knowledge. It is the natural content for
the `skills/` summaries the [system prompt](../ai_framework/agent/system.py) already reserves a
slot for, and for a future `knowledge_base/` retrieval layer.

---

## 3. How it feeds the agent

### 3.1 As skills (system-prompt summaries)
Today `build_system_prompt` lists tool schemas; the design (INTEGRATION_PLAN §2.1) also folds in
**skill summaries**. Each corpus file → one skill: a short title + 1–2 line "when this applies"
extracted from its decision tree. The agent sees the *menu* of techniques without paying for the
full text — and [Headroom](../ai_framework/headroom/README.md) keeps that menu inside the budget.

### 3.2 As a retrieval source (knowledge_base/)
The full file is too large to inject wholesale (`authentication.md` alone is ~14k lines —
larger than most context windows). The fit: **retrieve on demand**. When the agent picks a
technique, pull only the relevant section of that file, and let Headroom's `truncate_log` /
summarize ladder bound it. The `README.md` decision tree is the routing key: observation →
candidate technique file.

### 3.3 As offline-backend routing
The [`OfflineBackend`](../ai_framework/models/offline.py) is heuristic and keyless. The decision
tree gives it real signal: e.g. a recon `log` containing `Server: nginx` or a reflected
parameter → propose the matching technique's first step. This makes the no-API-key demo
meaningfully smarter without a model.

### 3.4 As memory seed
Technique facts can be pre-loaded as `MemoryRecord(kind=target_fact|lesson)` so the agent
recalls them via the now-wired memory injection (`with_memory`) — and so the **anti-loop**
machinery can mark a technique a dead end for a given target.

### 3.5 For defense (`defense/`)
Every file's defensive notes invert the objective: the same loop, reused unchanged, can audit a
target *against* each class's mitigations (INTEGRATION_PLAN §7 — defense reuses the engine).

---

## 4. Constraints & cautions

- **Authorization first.** This is offensive technique knowledge. It only ever drives a run
  bounded by `RunConfig.authorized_targets` and the [tool safety gate](../ai_framework/tools/README.md).
  Knowing a technique never bypasses the authorized-target check.
- **External & unversioned.** The corpus lives outside the repo and is not pinned. Any
  integration must treat its path as configuration and fail soft if absent (offline demo must
  still run with no knowledge base).
- **Bilingual content.** Some files (e.g. `recon.md`) are Vietnamese; skill summaries and
  synopses should pass through the planned `i18n/` layer rather than assume English.
- **Filenames are as-found** (`os_comand.md`, `web_chace_poisoning.md`, `webshotket.md` contain
  typos). Reference them by exact name; don't "correct" them in code paths.

---

## 5. Suggested next step

Add a thin, optional loader: `ai_framework/skills/` reads a configured corpus directory, emits
`{title, when_applies, file}` skill summaries for the system prompt, and exposes a
`section(technique, query)` retrieval call for §3.2 — gated so a missing corpus degrades to the
current keyless demo. This turns the corpus from reference material into a live agent capability
without changing the loop.
