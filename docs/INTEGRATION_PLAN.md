# Integration Plan — Hermes Agent & Headroom

> A design + roadmap document for folding two capabilities into the existing
> [`ai_framework/`](../ai_framework/README.md):
>
> 1. **Hermes Agent** — a concrete reasoning loop + tool-calling protocol + persistent
>    memory, adopted from NousResearch / **hermes-agent** (already named as the inspiration
>    for [`agent/`](../ai_framework/agent/README.md) and
>    [`memory/`](../ai_framework/memory/README.md)). This plan turns that inspiration into
>    an implementable contract.
> 2. **Headroom** — a new cross-cutting **context-window management** subsystem: token
>    accounting, transcript/memory compaction, and a budget that keeps reasoning "headroom"
>    so long, multi-step pentest runs never overflow the model's context.
>
> Skeleton stage: this is design, not code. It is written to be consistent with
> [`../README.md`](../README.md) and [`../ARCHITECTURE.md`](../ARCHITECTURE.md), and all
> documents stay English-only (project rule).

---

## 1. Why these two, and how they relate

The framework's core is an **observe → reason → act → observe** loop with a log-driven
planner (see [`ARCHITECTURE.md`](../ARCHITECTURE.md#inside-the-ai-framework--the-loop)).
A long pentest run produces a lot of evidence: tool logs, recalled memory, loaded skills,
and per-step reasoning. Two problems follow naturally:

- **The loop needs a disciplined contract** for *how* the model proposes actions and *how*
  results flow back — so steps are inspectable, replayable, and tool calls are
  unambiguous. → **Hermes Agent** supplies this.
- **The context window is finite.** Without management, a long run either truncates
  silently (losing critical findings) or pays to re-send the whole transcript every step.
  → **Headroom** supplies this.

They are complementary: Hermes defines *what* goes into each model call; Headroom governs
*how much* and decides what to keep, summarize, or drop. Headroom sits **between** the
agent loop and the [`models/`](../ai_framework/models/README.md) backend.

```
  agent loop ──builds turn──▶ [ Headroom ] ──fitted context──▶ models backend
       ▲                          │  (accounts tokens, compacts,
       │                          │   pulls only relevant memory)
       └───── parsed actions ◀────┘
```

---

## 2. Part A — Hermes Agent

### 2.1 What we adopt

From hermes-agent we take three things, mapped onto existing directories — **no new
top-level directory is required**:

| Hermes concept                | Lands in                                                        |
|-------------------------------|-----------------------------------------------------------------|
| Structured tool-calling loop  | [`ai_framework/agent/`](../ai_framework/agent/README.md)        |
| Tool-call / result protocol   | [`ai_framework/tools/`](../ai_framework/tools/README.md) (I/O shape) + agent |
| Persistent, recallable memory | [`ai_framework/memory/`](../ai_framework/memory/README.md)      |

### 2.2 The turn protocol (the contract)

Each loop iteration is one **turn**. A turn is a structured exchange so it can be logged,
diffed, and replayed:

1. **System** — role, authorized target, safety constraints, the loaded skill summaries,
   and the available tool schemas.
2. **Assistant (reason + act)** — the model emits, in order:
   - a short **reasoning / scratchpad** segment (kept out of long-term memory by default), and
   - zero or more **tool calls**, each as a structured object `{ name, arguments }`
     validated against the tool's declared schema.
3. **Tool results** — each call's output (the **pentest LOG**) is appended as a result
   message keyed to the call id.
4. **Log-driven planning** — the agent feeds *that turn's* logs back in and the model emits
   the **next plan** (the capability the brief calls out). Plan → becomes the next turn's
   focus.

The model backend's existing contract already returns "either text or a list of tool
calls" ([`models/`](../ai_framework/models/README.md#the-contract)) — Hermes just fixes the
*schema* of those tool calls and the *ordering* of segments within a turn.

### 2.3 Backend compatibility

- **Anthropic/Claude backend** — uses native tool-use; the Hermes turn maps onto Claude's
  `tool_use` / `tool_result` blocks. The reasoning segment maps to Claude's thinking.
- **Offline backend** — emits Hermes-style tool calls heuristically from matched skills, so
  the loop is demonstrable with no API key (preserves the existing offline goal).

A thin **prompt/format adapter** normalizes both into the one turn protocol above. This is
the only new seam Hermes adds to `models/`.

### 2.4 Memory (Hermes-style), concretely

Formalize [`memory/`](../ai_framework/memory/README.md) into three record kinds, each a
small structured entry with a stable id and timestamps:

- **target_fact** — stack, endpoints, observed behaviours, in-scope credentials.
- **attempt** — technique tried, inputs, outcome (worked / failed / inconclusive), the log
  reference. Prevents re-trying dead ends (anti-loop).
- **lesson** — generalizable, reusable-across-runs takeaway.

**Recall** ranks entries by `(target match, technique match, recency)` and returns only the
top-K to re-enter context. This ranking is what Headroom calls when it has to choose *which*
memory to spend tokens on (see §3.3). Notes stay human-curated and distinct, per the
existing README.

---

## 3. Part B — Headroom (context-window management)

### 3.1 Goal

Keep every model call **inside the window with deliberate slack** ("headroom") reserved for
the model's own output, so multi-step runs are bounded, predictable, and never silently
truncated. It is a cross-cutting concern, like [`i18n/`](../i18n/README.md): one component
that the agent loop and `models/` both rely on.

### 3.2 Placement

New module: **`ai_framework/headroom/`** (sibling to `models/`). It does not reason; it
*measures and shapes* what reaches the reasoning backend.

```
ai_framework/
├── agent/        reasoning loop + log-driven planner   (Hermes)
├── headroom/     ← NEW: context budgeting & compaction
├── memory/       persistent facts                       (Hermes-style)
├── models/       pluggable LLM backends
├── skills/  tools/  research/  notes/
```

### 3.3 Responsibilities

1. **Token accounting** — estimate/count tokens for system, skills, memory, transcript, and
   tool schemas before each call. (Claude backend can use exact token counting; offline uses
   a fast heuristic.)
2. **Budget policy** — a per-run budget split into reserved slices:
   `system + tool schemas` (fixed) · `memory recall` (top-K) · `recent transcript` ·
   `**reserved output headroom**` (never consumed by input). If the assembled input would
   eat into reserved output headroom, compaction triggers.
3. **Compaction** — when over budget, in priority order:
   - drop the oldest **reasoning/scratchpad** segments (cheapest to lose),
   - **summarize** older turns into a rolling synopsis (the summary is stored as a memory
     `lesson`/synopsis so nothing important is truly lost),
   - shrink **memory recall** to a smaller top-K (calls `memory.recall`, §2.4),
   - last resort: truncate large tool logs to head+tail with an explicit `[…truncated N
     lines…]` marker.
4. **No silent loss** — every compaction action is recorded in the turn transcript so the
   Agent Console can show "summarized 6 turns", "truncated nmap log". Visibility is a hard
   requirement.

### 3.4 The contract

```
fit(turn_request, budget) -> fitted_request + compaction_report
```

`fit()` is called by the agent loop just before each `models/` call. It never changes the
*meaning* of the turn protocol (§2.2) — it only chooses what to include and how densely.
Swapping models (different window sizes) changes only the `budget`, not the loop.

### 3.5 Configuration

Headroom reads from the backend's single config source
([`ARCHITECTURE.md` › Cross-cutting](../ARCHITECTURE.md#cross-cutting-concerns)):

- `context_window` / `max_output` (per active model backend),
- `reserved_output_headroom` (default e.g. 25% of window),
- `memory_recall_k`, `summarize_after_turns`, `max_tool_log_tokens`,
- `step_budget` (the existing loop stop condition; Headroom reports remaining budget).

---

## 4. Cross-cutting touch-points

- **`i18n/`** — summaries/synopses are content; English is canonical, VI on demand via
  `models/`, consistent with the
  [multi-language architecture](../ARCHITECTURE.md#multi-language-architecture-i18n).
- **`backend/`** — exposes Headroom's compaction report and remaining-budget on the
  step-logging / run endpoints so the Agent Console can render them.
- **`defense/`** — inherits both for free: it reuses `agent/` + `models/`, so Hermes turns
  and Headroom budgeting apply unchanged when reviewing a codebase.
- **`docs/`** — the exact record shapes (target_fact / attempt / lesson, turn, compaction
  report, budget) belong in this directory's planned **Data contracts**.

---

## 5. Phased roadmap

Ordered to deliver a demonstrable loop early, then make it robust.

| Phase | Deliverable | Depends on |
|------|-------------|------------|
| **0. Contracts** | Write the data contracts in `docs/`: turn, tool-call/result, memory records, budget, compaction report. No code. | — |
| **1. Hermes loop (offline)** | Implement the turn protocol in `agent/` against the **offline** backend; emit + parse tool calls; log every turn. | Phase 0 |
| **2. Memory** | `memory/` write + recall (top-K ranking); anti-loop via `attempt` records. | Phase 1 |
| **3. Claude backend adapter** | Map the Hermes turn onto Claude tool-use + thinking; exact token counting. | Phase 1 |
| **4. Headroom — accounting** | `ai_framework/headroom/`: token accounting + budget policy with reserved output headroom; `fit()` as a pass-through that only *reports*. | Phase 2, 3 |
| **5. Headroom — compaction** | Enable the compaction ladder (§3.3); store synopses as memory; surface compaction report. | Phase 4 |
| **6. Surface in UI/API** | `backend/` endpoints expose budget + compaction; Agent Console streams them. | Phase 5 |
| **7. Defense reuse** | Confirm `defense/` runs the same loop unchanged. | Phase 5 |

A minimal end-to-end demo (no API key) is reachable at the end of **Phase 5**.

---

## 6. Open questions

- **Tokenizer for the offline backend** — heuristic char/word ratio vs. a bundled
  tokenizer. Start heuristic; revisit if estimates drift too far from Claude's exact counts.
- **Summarizer model on offline runs** — without an API key, "summarize older turns" must
  degrade to extractive truncation. Confirm that's acceptable for the offline demo.
- **Reserved-headroom default** — 25% is a starting guess; tune against real run lengths.
- **Where synopses live** — a dedicated `memory` synopsis kind vs. reusing `lesson`.

---

## 7. Documentation changes this plan implies

When work starts (not now — skeleton stage), these READMEs should be updated to reference
this plan:

- [`ai_framework/README.md`](../ai_framework/README.md) — add `headroom/` to the parts table.
- [`ai_framework/agent/README.md`](../ai_framework/agent/README.md) — point to the §2.2 turn
  protocol as the concrete contract.
- [`ai_framework/memory/README.md`](../ai_framework/memory/README.md) — name the three
  record kinds and the recall ranking.
- [`ai_framework/models/README.md`](../ai_framework/models/README.md) — note the Hermes
  format adapter and that Headroom sits in front of the backend.
- [`ARCHITECTURE.md`](../ARCHITECTURE.md) — add Headroom to the component table and the loop
  diagram.

**Status:** implemented. Hermes loop (Phases 0–3, 6–7) and Headroom accounting +
compaction (Phases 4–5) are coded under `ai_framework/` with tests; `fit()` is wired into
the agent loop (opt-in via `Budget`), the CLI demo (`--headroom`), and `backend/RunService`.
