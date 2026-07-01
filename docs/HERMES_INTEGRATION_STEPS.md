# Hermes Agent — Step-by-Step Integration Plan

> **Scope:** integrate the **Hermes-style agent loop** (NousResearch / hermes-agent) into
> `ai_framework/` — from an empty Python package to a **running, tested** observe → reason →
> act → observe loop with persistent memory and log-driven planning.
>
> This is the **execution** companion to [`INTEGRATION_PLAN.md`](INTEGRATION_PLAN.md) (which
> is the *design*). Here every step is concrete, ordered, and ends with a **verify**
> checkpoint. Headroom (context budgeting) is deliberately deferred — finish a working
> Hermes loop first, then layer Headroom on top.

**Language:** Python 3.11+. **Goal of "done":** `pytest` green + a CLI demo that runs a full
multi-turn loop against the **offline** backend with **no API key**, then the same loop
against the **Claude** backend when a key is present.

---

## Step 0 — Project setup (Python package + tooling)

1. Create the Python project at the repo root:
   - `pyproject.toml` (package name `secforge`, Python ≥ 3.11).
   - Dev deps: `pytest`, `ruff`, `mypy`, `pydantic` (data contracts), `anthropic` (Claude
     backend, optional at runtime), `tiktoken` *(later, for Headroom)*.
2. Make `ai_framework/` an installable package: add `__init__.py` to `ai_framework/` and
   each sub-module (`agent/`, `memory/`, `models/`, `skills/`, `tools/`).
3. Add `.env.example` with `SECFORGE_MODEL_BACKEND=offline` and `ANTHROPIC_API_KEY=`.
4. Add `make` / scripts: `make test`, `make lint`, `make demo`.

**✅ Verify:** `pip install -e .` succeeds; `pytest` runs (0 tests, exits clean);
`python -c "import ai_framework"` works.

---

## Step 1 — Data contracts (the turn protocol, in code)

Implement [`INTEGRATION_PLAN.md` §2.2 / §2.4](INTEGRATION_PLAN.md) as **pydantic models** in
`ai_framework/agent/contracts.py`:

- `ToolCall { id, name, arguments: dict }`
- `ToolResult { call_id, log: str, ok: bool }`
- `Turn { index, reasoning: str, tool_calls: list[ToolCall], tool_results: list[ToolResult], next_plan: str }`
- `MemoryRecord` with kind ∈ `{target_fact, attempt, lesson}`, plus `id`, `created_at`,
  `target`, `technique`, `body`.
- `RunConfig { goal, target, step_budget, backend }`.

**✅ Verify:** unit test round-trips each model through `.model_dump_json()` /
`.model_validate_json()`; invalid tool arguments raise a validation error.

---

## Step 2 — Tool registry + two real tools

In `ai_framework/tools/`:

1. `base.py` — a `Tool` protocol: `name`, `json_schema` (args schema), `run(args) -> str`
   (returns the **log**). A `ToolRegistry` that holds tools and emits their schemas for the
   system prompt.
2. Two safe, deterministic starter tools (no real network needed for tests):
   - `http_get` — fetch a URL (allow-listed / localhost only; mockable).
   - `note_finding` — write a structured finding (pure, always testable).
3. **Safety gate:** any tool touching a real target checks an `authorized_targets` set from
   `RunConfig`; unauthorized → refuse with a logged error (per `ARCHITECTURE.md` safety).

**✅ Verify:** test that the registry serializes schemas; `http_get` against a localhost
mock returns a log; an unauthorized target is refused.

---

## Step 3 — Model backend interface + offline backend

In `ai_framework/models/`:

1. `base.py` — `Backend.complete(system, messages, tools) -> BackendResponse` where the
   response is **either text or a list of `ToolCall`s** (the existing model contract).
2. `offline.py` — heuristic backend: from the loaded skills + last log, emit a Hermes-style
   tool call (e.g. "no recon yet → call `http_get`"; "got a 200 → `note_finding`"), then a
   plain-text `next_plan`. **No network, no key.** This is what makes the loop demoable.

**✅ Verify:** given a synthetic conversation, `offline.complete()` returns a valid
`ToolCall` the registry can execute; deterministic across runs.

---

## Step 4 — The Hermes loop (offline end-to-end)

In `ai_framework/agent/loop.py` — implement the turn protocol from §2.2:

1. Build the **system** message: role, authorized target, safety constraints, skill
   summaries, tool schemas.
2. Loop until `done` or `step_budget` reached. Each iteration:
   a. `model.complete(...)` → reasoning + tool calls.
   b. Execute each tool call via the registry → `ToolResult` (the log).
   c. **Log-driven planning:** feed the logs back; model emits `next_plan`.
   d. Append a fully-populated `Turn` to the transcript.
3. Return a `Run` object: config + ordered transcript + outcome.

**✅ Verify:** an integration test runs a ≥3-turn loop on the offline backend and asserts:
each turn has reasoning + ≥1 executed tool call + a `next_plan`; the loop halts at
`step_budget`; the transcript replays from JSON identically.

---

## Step 5 — Persistent memory (Hermes-style) + anti-loop

In `ai_framework/memory/` (implements §2.4):

1. `store.py` — write/read `MemoryRecord`s to a JSON-lines file (swap to SQLite later);
   persists **across sessions**.
2. `recall(target, technique, k)` — rank by `(target match, technique match, recency)`,
   return top-K.
3. Wire into the loop: **write** an `attempt` record after each tool call; **recall** before
   each `model.complete` and inject into context. **Anti-loop:** if an `attempt` with the
   same `(technique, target, args)` already failed, the loop must not repeat it.

**✅ Verify:** test that a second run reads the first run's memory file; recall returns the
most relevant top-K; a repeated dead-end attempt is suppressed.

---

## Step 6 — Claude backend adapter

In `ai_framework/models/anthropic_backend.py`:

1. Map the Hermes turn onto Claude **native tool-use**: tool schemas → `tools`, `ToolCall`
   ↔ `tool_use` block, `ToolResult` ↔ `tool_result` block; reasoning ↔ thinking.
2. Default model `claude-opus-4-8`; key from `ANTHROPIC_API_KEY` env var (never in files).
3. Selected when `RunConfig.backend == "anthropic"`; **the loop code does not change** — only
   the backend swaps.

**✅ Verify:** with a key present, the same Step 4 integration test passes against the
Claude backend (gate behind `@pytest.mark.skipif(no key)`); without a key it cleanly falls
back to offline.

---

## Step 7 — CLI demo

`python -m ai_framework.demo --goal "..." --target http://localhost:8000 --backend offline`

- Streams each turn (reasoning → tool calls → logs → next plan) to the console.
- Prints the final transcript + memory written.

**✅ Verify (the "successful" gate):** running the demo with **no API key** completes a full
multi-turn run against a localhost mock target and prints a coherent transcript +
persisted memory. Re-running picks up prior memory.

---

## Step 8 — Tests, lint, and CI gate

1. `pytest` suite: contracts, tools, offline backend, loop, memory, (skipped) Claude.
2. `ruff` + `mypy` clean.
3. A GitHub Actions workflow running `make lint && make test` on push.

**✅ Verify:** CI is green on a fresh checkout with no secrets configured.

---

## Step 9 — Wire into backend + docs

1. `backend/` exposes `POST /runs` (start) and `GET /runs/{id}` (stream transcript) over the
   loop — minimal, just enough for the Agent Console.
2. Update the skeleton READMEs to point at the real code (per
   [`INTEGRATION_PLAN.md` §7](INTEGRATION_PLAN.md)).
3. Confirm `defense/` can call the same loop unchanged (objective inverted, engine reused).

**✅ Verify:** `curl POST /runs` returns a run id; `GET /runs/{id}` streams the same turns
the CLI produced.

---

## Definition of done

- [ ] `pytest` green; `ruff` + `mypy` clean; CI passing with no secrets.
- [ ] Offline demo completes a multi-turn Hermes loop and persists memory (no API key).
- [ ] Same loop runs against the Claude backend when `ANTHROPIC_API_KEY` is set.
- [ ] Memory survives across sessions; dead-end attempts are not repeated (anti-loop).
- [ ] Every turn is logged and replayable from JSON.
- [ ] Backend endpoints expose a run; `defense/` reuses the loop unchanged.

**Next after this:** layer **Headroom** (context budgeting / compaction) on top —
[`INTEGRATION_PLAN.md` §3 + Phases 4–5](INTEGRATION_PLAN.md).
```

