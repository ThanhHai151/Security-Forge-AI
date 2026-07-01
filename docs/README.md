# `docs/` — Design Notes & Specifications

Home for deeper design material that doesn't belong in a single module's README.

The two **project-wide overviews** live at the repository root, not here:
- [`../README.md`](../README.md) — capabilities overview.
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — structure & data flow.

## Design notes in this folder

- [`INTEGRATION_PLAN.md`](INTEGRATION_PLAN.md) / [`HERMES_INTEGRATION_STEPS.md`](HERMES_INTEGRATION_STEPS.md)
  — Hermes agent + Headroom design and build steps.
- [`KNOWLEDGE_BASE.md`](KNOWLEDGE_BASE.md) — the web-security technique corpus and how it feeds the agent.
- [`SKILLS_AND_I18N.md`](SKILLS_AND_I18N.md) — skill-manifest format and bilingual architecture.
- [`EXTERNAL_TOOLKITS.md`](EXTERNAL_TOOLKITS.md) — how the three upstream toolkits (hackingtool,
  Anthropic-Cybersecurity-Skills, Claude-BugHunter) fold into SecForge's pillars, and the safety
  boundary that keeps their catalogs knowledge-only.
- [`AUTONOMOUS_PENTEST.md`](AUTONOMOUS_PENTEST.md) — the continuous ("infinite") campaign layer:
  the `#/auto` terminal, the tried/untried coverage map, the between-phase continue/stop prompt,
  the hold-for-approval gate on state-changing actions, and stealth defaults.
- [`RED_TEAM_OPSEC.md`](RED_TEAM_OPSEC.md) ([Tiếng Việt](RED_TEAM_OPSEC.vi.md)) — red-team stealth / OPSEC
  & evasion tradecraft (source concealment, time/locale, traffic blending, host evasion, footprint
  management), each technique paired with its blue-team **detection counterpart** for the
  [`../defense/`](../defense/README.md) pillar.

## Planned contents

- **API specification** — endpoint shapes once the backend is designed.
- **Data contracts** — the exact shapes for KB documents, skill manifests, tool I/O,
  memory/notes entries, and lab metadata.
- **Glossary** — shared vocabulary (also feeds the [`../i18n/`](../i18n/README.md) term
  glossary).
- **Roadmap** — build order and milestones.

All documents here are in **English** (project rule).

**Status:** the Hermes + Headroom design ([`INTEGRATION_PLAN.md`](INTEGRATION_PLAN.md),
[`HERMES_INTEGRATION_STEPS.md`](HERMES_INTEGRATION_STEPS.md)) is implemented; the remaining
pillars (knowledge base, vuln search, defense, router, i18n) are coded and wired into the
backend/frontend. Each pillar's README carries its own module map and HTTP route.
