# `ai_framework/models/` — Pluggable LLM Backends

The reasoning supply for the framework. A single backend interface so the
[`agent`](../agent/README.md), [`research`](../research/README.md), and
[`../../defense/`](../../defense/README.md) don't care *which* model is behind it.

## Planned backends

- **Claude backend** — the primary backend, using Anthropic's Claude
  (default model `claude-opus-4-8`, adaptive thinking, effort control). Activated when an
  API key is configured. This is also what powers on-demand EN ⇄ VI content translation
  for [`../../i18n/`](../../i18n/README.md).
- **Offline backend** — a heuristic, no-network fallback that produces a plan from the
  matched skills, so the loop is demonstrable without any API key.

## The contract

A backend turns `(system prompt, conversation, available tools)` into either text or a
list of tool calls. Swapping backends must not change how the agent loop is written.

## Connects to

- [`../agent/`](../agent/README.md) · [`../research/`](../research/README.md) — consumers.
- [`../../backend/`](../../backend/README.md) — chooses the backend from config; supplies
  the API key from an environment variable (never hard-coded).
- [`../../i18n/`](../../i18n/README.md) — on-demand translation of content.

## Notes

- Which backend is active is a config choice (`offline` vs `anthropic`).
- The key comes from an environment variable; secrets never live in files.

**Status:** implemented — `base.py` (Backend protocol), `offline.py` (heuristic, no key),
`anthropic_backend.py` (Claude native tool-use, `claude-opus-4-8`).
