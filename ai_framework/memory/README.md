# `ai_framework/memory/` — Persistent Memory (Hermes-style)

So the agent doesn't start from zero every step or every session. Memory holds durable
facts — about the target, about what's been tried, and lessons learned — and surfaces the
relevant ones back into the loop.

## What gets remembered

- **Target facts** — stack, endpoints, observed behaviours, credentials in scope.
- **Attempt history** — what was tried, what worked, what didn't (so the agent doesn't
  loop).
- **Lessons** — generalizable takeaways, reusable across future runs.

## Behaviour

- **Write** as the [`agent`](../agent/README.md) observes results.
- **Recall** — surface the entries relevant to the current step (by target, technique, or
  recency) so they re-enter the model's context.
- **Persist across sessions** — memory outlives a single run; a later session can pick up
  where an earlier one left off.

## Connects to

- [`../agent/`](../agent/README.md) — reads and writes memory each step.
- [`../notes/`](../notes/README.md) — notes are human-curated; memory is agent-managed
  working state. They're related but distinct.

## Inspired by

NousResearch / **hermes-agent** — its memory capability.

**Status:** implemented — `store.py` provides JSON-lines persistence, top-K `recall`, and
the `has_failed_attempt` anti-loop guard (record kinds: `target_fact`, `attempt`, `lesson`).
