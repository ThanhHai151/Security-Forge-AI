# `ai_framework/` — The AI Pentest Framework

**Pillar 2.** The default Expert Supervisor classifies an application, ranks techniques,
loads one skill per vulnerability, and turns each skill's logical questions into a briefing
for an external testing agent. The separate legacy executor retains an opt-in
observe → reason → act loop. The same knowledge, pointed inward, supports
[`../defense/`](../defense/README.md).

## The parts

| Sub-module                       | Role                                                             |
|----------------------------------|------------------------------------------------------------------|
| [`harness/`](../docs/RED_TEAM_AGENT_HARNESS.md) | Typed RoE, policy gates, phases, vendor adapters.   |
| [`supervisor/`](supervisor/README.md) | Default advisory planner + evidence-led question engine.    |
| [`agent/`](agent/README.md)       | The reasoning loop **and the log-driven next-step planner**.     |
| [`skills/`](skills/README.md)     | 29 one-to-one vulnerability skills + 3 OPSEC skills.             |
| [`tools/`](tools/README.md)       | A categorised catalog of runnable actions (recon, http, …).      |
| [`memory/`](memory/README.md)     | Persistent facts, kept across steps and across sessions.         |
| [`research/`](research/README.md) | Self-research to fill gaps the knowledge base doesn't cover.     |
| [`notes/`](notes/README.md)       | Structured, reviewable findings and to-dos.                      |
| [`models/`](models/README.md)     | Pluggable LLM backend that supplies the reasoning.               |
| [`headroom/`](headroom/README.md) | Context-window budgeting & compaction in front of the backend.   |

## Default advisory path

```
domain + question + RoE ─▶ harness preflight/gates ─▶ archetype/taxonomy ranking
                                                    │
                                                    ▼
                                              selected skills
                                                    │
                                                    ▼
                                  staged evidence questions + plan
                                                    │
                                                    ▼
                                     external agent + notebook ingest
```

The legacy executor loads the same skills, calls the configured model/tools, and replans from
logs, but remains disabled until explicitly enabled.

Full diagram and component contracts: [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

## Inspirations (per the brief)

- **hermes-agent** → the [`agent/`](agent/README.md) loop and [`memory/`](memory/README.md).
- **Anthropic-Cybersecurity-Skills** → [`skills/`](skills/README.md).
- **hackingtool** → the [`tools/`](tools/README.md) catalog.

## Connects to

- [`../knowledge_base/`](../knowledge_base/README.md) — skills reference KB documents.
- [`../vuln_search/`](../vuln_search/README.md) — supplies candidate vulnerabilities.
- [`../defense/`](../defense/README.md) — reuses agent + skills + models for hardening.
- [`../backend/`](../backend/README.md) — exposes runs and step-logging over the API.

## Safety

The advisory harness blocks target traffic until written authorization, explicit scope, and an
active timezone-aware window are supplied. It returns machine-readable gates and a copy-ready
briefing; the external agent host must enforce them with its sandbox/permissions/hooks. Legacy
tools retain their separate scope gate. The framework is for authorized testing, CTFs, and
defending your own projects.

**Status:** implemented. The advisory path is the default; autonomous execution is opt-in.
