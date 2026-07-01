# `ai_framework/notes/` — Note-Taking

Structured capture of what matters during a run: findings, payloads that worked, open
questions, and to-dos. Human-readable and reviewable in the UI; also reusable by the
[`agent`](../agent/README.md).

## What a note holds

- A type (finding / payload / question / to-do).
- The target and the step it came from.
- A short body, and a link to the relevant
  [`knowledge_base`](../../knowledge_base/README.md) note or
  [`skill`](../skills/README.md) where applicable.
- A timestamp and tags for filtering.

## Notes vs. memory

- **Notes** are curated, human-facing output — the report you read after a run.
- [**Memory**](../memory/README.md) is the agent's internal working state.
- A note can be promoted from a memory entry, and vice versa.

## Connects to

- [`../agent/`](../agent/README.md) — creates notes as it works.
- [`../../frontend/`](../../frontend/README.md) — displays and lets you edit them.
- [`../../i18n/`](../../i18n/README.md) — note bodies carry a language tag (English source;
  Vietnamese on demand).

**Status:** skeleton — directory purpose only.
