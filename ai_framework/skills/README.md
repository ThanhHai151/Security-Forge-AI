# `ai_framework/skills/` — On-Demand Security Knowledge

Each *skill* is a compact, structured description of a vulnerability class that the
[`agent`](../agent/README.md) loads only when relevant — progressive disclosure, so the
model isn't drowned in all 32 topics at once.

## What a skill describes

- **When it applies** — the signals that make this technique worth trying.
- **Backing document** — the [`knowledge_base`](../../knowledge_base/README.md) note that
  holds the full write-up (so a skill stays small and points to depth on demand).
- **Suggested tools** — entries in [`tools/`](../tools/README.md) that help exploit it.
- **Example payloads / steps** — a few concrete starting points.
- **Secure-implementation notes** — so the same skill serves
  [`../../defense/`](../../defense/README.md), not just offense.

## Planned contents

- A skill **manifest** format (one file per skill), plus a `_template` to copy.
- One manifest per KB topic (`sql_injection`, `xss`, `ssrf`, `ssti`, `jwt`, `xxe`, …),
  generated from the existing notes.
- A small loader/registry that discovers manifests automatically.

## Connects to

- [`../../knowledge_base/`](../../knowledge_base/README.md) — every skill links to a note.
- [`../agent/`](../agent/README.md) — selects and loads skills per step.
- [`../tools/`](../tools/README.md) — skills recommend tools.

## Source corpus

The 32 technique topics are sourced from the web-security knowledge corpus (the vuln catalog
under `vuln_search/catalog/`). A thin loader here turns each file into a skill summary for the
system prompt + an on-demand retrieval call.

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

**Status:** skeleton — directory purpose only.
