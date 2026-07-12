# `ai_framework/skills/` — On-Demand Security Knowledge

Each *skill* is a compact, structured description of one vulnerability class that the
Expert Supervisor or legacy [`agent`](../agent/README.md) loads only when relevant —
progressive disclosure, so the consumer is not drowned in all 32 skills at once.

## What a skill describes

- **When it applies** — the signals that make this technique worth trying.
- **Backing document** — the [`knowledge_base`](../../knowledge_base/README.md) note that
  holds the full write-up (so a skill stays small and points to depth on demand).
- **Suggested tools** — entries in [`tools/`](../tools/README.md) that help exploit it.
- **Example payloads / steps** — a few concrete starting points.
- **Reasoning questions** — an ordered surface → context/fingerprint → validation → impact
  hypothesis chain, including explicit branch conditions.
- **Secure-implementation notes** — so the same skill serves
  [`../../defense/`](../../defense/README.md), not just offense.

## Implemented coverage

- 29 one-to-one vulnerability manifests: exactly one skill for every catalog entry.
- 3 cross-cutting OPSEC manifests.
- A loader/registry that discovers manifests, routes them through their `catalog` link, and
  parses staged `## Reasoning Questions` on demand.

The question bullet format is deliberately small:

```markdown
- [surface] Which input reaches the sink?
- [fingerprint | if paired controls differ] Which implementation is supported by evidence?
```

The text before `|` is the stage; the optional text after it is the branch condition. The
Supervisor returns typed questions with stable ids and dependencies, and its briefing tells
the external agent to answer them from evidence and prune unsupported branches.

## Connects to

- [`../../knowledge_base/`](../../knowledge_base/README.md) — every skill links to a note.
- [`../agent/`](../agent/README.md) — selects and loads skills per step.
- [`../tools/`](../tools/README.md) — skills recommend tools.

## Source corpus

The 29 vulnerability skills are sourced from the web-security catalog under
`vuln_search/catalog/`; the remaining 3 are cross-cutting OPSEC skills. A thin loader turns
each file into a compact trigger, taxonomy route, full on-demand workflow, and question chain.

## Format & i18n

Skills follow the [agentskills.io](https://agentskills.io) `SKILL.md` standard (YAML frontmatter +
four sections: When to Use · Prerequisites · Workflow · Verification) and are **bilingual**
(English canonical `SKILL.md` + Vietnamese `SKILL.vi.md` sibling, one language loaded at a time).

- Template: [`SKILL_TEMPLATE.md`](SKILL_TEMPLATE.md)
- Worked example: [`exploiting-sql-injection/`](exploiting-sql-injection/SKILL.md)
  ([Tiếng Việt](exploiting-sql-injection/SKILL.vi.md))

## Inspired by

**Anthropic-Cybersecurity-Skills** — structured skills loaded on demand (agentskills.io).
**hackingtool** — category taxonomy + executable tool-runner blueprint (future tool layer).

**Status:** implemented — 29/29 vulnerability entries have a one-to-one reasoning skill.
