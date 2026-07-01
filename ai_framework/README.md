# `ai_framework/` — The AI Pentest Framework

**Pillar 2.** The engine that drives a penetration test the way a person would: choose a
technique, run a tool, read the result, decide the next move — adapting as it goes instead
of following a fixed script. The same engine, pointed inward, powers
[`../defense/`](../defense/README.md).

## The parts

| Sub-module                       | Role                                                             |
|----------------------------------|------------------------------------------------------------------|
| [`agent/`](agent/README.md)       | The reasoning loop **and the log-driven next-step planner**.     |
| [`skills/`](skills/README.md)     | On-demand security knowledge; each KB topic becomes a skill.     |
| [`tools/`](tools/README.md)       | A categorised catalog of runnable actions (recon, http, …).      |
| [`memory/`](memory/README.md)     | Persistent facts, kept across steps and across sessions.         |
| [`research/`](research/README.md) | Self-research to fill gaps the knowledge base doesn't cover.     |
| [`notes/`](notes/README.md)       | Structured, reviewable findings and to-dos.                      |
| [`models/`](models/README.md)     | Pluggable LLM backend that supplies the reasoning.               |
| [`headroom/`](headroom/README.md) | Context-window budgeting & compaction in front of the backend.   |

## How they work together

```
goal + target
   │
   ├─▶ agent loads relevant skills ──▶ model proposes the next action
   │                                        │
   │                                        ▼
   │                                   tools run it ──▶ pentest LOGS
   │                                        │
   │      agent reads logs, updates memory + notes
   │      (research fills gaps when skills fall short)
   │                                        │
   └──── log-driven planner: produce the next step ◀───┘   (repeat)
```

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

Tools that touch a real target must require the user to authorize that target explicitly.
The framework is for authorized testing, CTFs, and defending your own projects.

**Status:** skeleton — directory purpose only.
