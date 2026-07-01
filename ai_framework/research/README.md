# `ai_framework/research/` — Self-Research

When the knowledge base doesn't cover what the agent just saw — an unfamiliar technology,
a new error, a CVE — this module goes and finds out, then folds the result back into the
agent's working knowledge.

## Responsibilities

- **Detect a gap** — the [`agent`](../agent/README.md) hits something the
  [`skills`](../skills/README.md) and [`knowledge_base`](../../knowledge_base/README.md)
  don't explain.
- **Research it** — query external sources (web, and the CVE feeds via
  [`../../vuln_search/`](../../vuln_search/README.md)).
- **Distill** — summarize findings into a form the agent can act on.
- **Remember** — write the distilled result into [`memory`](../memory/README.md) (and
  optionally propose a new [`skill`](../skills/README.md)) so the gap is closed for next
  time.

## Connects to

- [`../../vuln_search/`](../../vuln_search/README.md) — CVE/technique lookups.
- [`../memory/`](../memory/README.md) — where results are retained.
- [`../models/`](../models/README.md) — used to summarize/distill sources.

## Safety

Honors the project-wide network policy (online lookups are opt-in via config) and cites
where each fact came from.

**Status:** skeleton — directory purpose only.
