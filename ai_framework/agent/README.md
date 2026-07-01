# `ai_framework/agent/` — Reasoning Loop & Log-Driven Planner

The orchestrator. Runs the **observe → reason → act → observe** loop and, crucially,
contains the **log-driven next-step planner** the brief asks for.

## Responsibilities

- **Run the loop** — for a goal and target: load relevant
  [`skills`](../skills/README.md), ask the [`model`](../models/README.md) for the next
  action, invoke a [`tool`](../tools/README.md), observe the result, repeat until done or a
  step budget is reached.
- **Log-driven planning** — after each step, take *that step's pentest logs* as input and
  **automatically generate the next execution plan**. The plan is derived from evidence,
  not a fixed playbook, which is what makes the run adaptive.
- **Persist as it goes** — write findings to [`memory`](../memory/README.md) and
  [`notes`](../notes/README.md); trigger [`research`](../research/README.md) when the
  knowledge base doesn't cover what was observed.
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
log-driven planner live in `loop.py` / `contracts.py` / `system.py`. See
[`docs/HERMES_INTEGRATION_STEPS.md`](../../docs/HERMES_INTEGRATION_STEPS.md).
