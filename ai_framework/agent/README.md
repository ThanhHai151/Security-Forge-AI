# `ai_framework/agent/` — Reasoning Loop & Log-Driven Planner

The orchestrator. Runs the **observe → reason → act → observe** loop and, crucially,
contains the **log-driven next-step planner** the brief asks for.

## Responsibilities

- **Run the loop** — for a goal and target: load relevant
  [`skills`](../skills/README.md), ask the [`model`](../models/README.md) for the next
  action, invoke a [`tool`](../tools/README.md), observe the result, repeat until done or a
  step budget is reached.
- **Log-driven planning** — after each step, take *that step's pentest logs* as input and
  **automatically generate the next execution plan** (`backend.plan`). The plan is then fed
  **back into the next `act` call** (`system.with_plan`) so it actually steers the next
  action — derived from evidence, not a fixed playbook, which is what makes the run adaptive.
- **Break bad loops** — `guardrails.py` (a hermes-style, side-effect-free controller) blocks
  calls that keep failing and halts a run that stops making progress, holding *mutating*
  tools to a tighter leash than idempotent recon.
- **OPSEC pacing** — `opsec.py` spaces network actions with a minimum interval + jitter so
  the cadence the system prompt warns about ("a perfectly regular beacon") isn't emitted.
- **Persist as it goes** — write facts/attempts to [`memory`](../memory/README.md), findings
  to [`notes`](../notes/README.md), and checkpoint the whole run to disk (`run_store.py`) so
  it survives a restart and can be replayed; trigger [`research`](../research/README.md) when
  the knowledge base doesn't cover what was observed.
- **Stay inspectable** — every step (thought, action, observation, next plan) is recorded
  so the Agent Console can stream it and a human can intervene.

## Inputs & outputs

- **In:** goal, authorized target, current step logs, available skills/tools, memory.
- **Out:** the next plan/action, an updated transcript, new memory + notes entries.

## Connects to

- [`../models/`](../models/README.md) — the reasoning backend.
- [`../skills/`](../skills/README.md) · [`../tools/`](../tools/README.md) — what it reasons
  over and acts with.
- [`../memory/`](../memory/README.md) · [`../notes/`](../notes/README.md) ·
  [`../research/`](../research/README.md) — persistence and gap-filling.
- [`../../backend/`](../../backend/README.md) — exposes "start run" and "submit step logs".

## Inspired by

NousResearch / **hermes-agent** — the agentic loop and its tool-calling style.

**Status:** implemented (offline + Claude backends). The Hermes turn protocol, loop, and
log-driven planner live in `loop.py` / `contracts.py` / `system.py`; the loop-breaker,
OPSEC pacer, and durable run store are `guardrails.py` / `opsec.py` / `run_store.py` (all
opt-in collaborators of `run_loop`).
