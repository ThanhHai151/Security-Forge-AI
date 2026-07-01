# Skills & Bilingual (EN/VI) Design

> How SecForge structures its **knowledge** so an agent (or a human) can discover and load it
> cheaply, and how every piece of that knowledge is maintained in **English + Vietnamese**.
>
> Grounded in two references the project follows:
> - **[Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)**
>   → the [agentskills.io](https://agentskills.io) `SKILL.md` standard (progressive disclosure).
> - **[hackingtool](https://github.com/Z4nzu/hackingtool)** → an executable tool-runner taxonomy
>   (categories + `TITLE/DESCRIPTION/INSTALL/RUN/SUPPORTED_OS`).

---

## 1. Two layers, one corpus

| Layer | What | Format | Lives in |
|-------|------|--------|----------|
| **Dictionary** | Human-readable vuln cards + "find CVEs from scratch" | Markdown card | [`vuln_search/catalog/<slug>/`](../vuln_search/catalog/INDEX.md) |
| **Skills** | Agent-loadable, structured procedures | agentskills.io `SKILL.md` | `ai_framework/skills/<kebab-name>/` |
| **Deep notes** | Long-form technique references | Markdown | `../Troubleshooting_Guide/` (external; see [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md)) |
| **Tool-runner** *(future)* | Executable tools, OS-aware | `Tool` class | `ai_framework/tools/` |

The **dictionary** is for reading/searching; **skills** are for the agent to *act*; the **deep
notes** are the source material both summarize. All three obey the same i18n rules (§3).

---

## 2. Skill format (agentskills.io)

Each skill is a folder under `ai_framework/skills/`, kebab-case after the skill:

```
skills/exploiting-sql-injection/
├── SKILL.md            ← canonical (English): YAML frontmatter + Markdown body
├── SKILL.vi.md         ← Vietnamese translation of the body (frontmatter mirrored)
├── references/         ← deep procedure / standards mappings (optional)
├── scripts/            ← helper scripts (optional)
└── assets/             ← templates, checklists (optional)
```

### Frontmatter (YAML)
```yaml
name: exploiting-sql-injection          # kebab-case, 1–64 chars, == folder name
description: >-                          # keyword-rich, one sentence, for discovery
  Detect and exploit SQL injection across error/union/blind/time-based variants,
  then report impact and remediation.
domain: web-application-security
subdomain: injection
tags: [sqli, injection, database, web, owasp-a03]
languages: [en, vi]                      # <-- SecForge i18n field (see §3)
owasp: [A03:2021-Injection]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../vuln_search/catalog/sql_injection/README.md   # link to the dictionary card
deep_dive: ../../../Troubleshooting_Guide/sql_injection.md
```

`description` + `tags` + `domain` are the **scan surface** — keep them keyword-rich. Framework
mappings (MITRE ATT&CK/ATLAS, D3FEND, NIST) go in `references/standards.md`, not frontmatter
(matches the reference repo).

### Body — four fixed headings
```
## When to Use      — trigger conditions (what observation activates this skill)
## Prerequisites    — tools, access, authorization required
## Workflow         — ordered, concrete steps + decision points
## Verification     — how to confirm success / a real finding
```

### Progressive disclosure (why this shape)
An agent scans **frontmatter only** (~30 tokens/skill) to shortlist, then loads the **full
body** (500–2k tokens) for the top matches. This is what makes [Headroom](../ai_framework/headroom/README.md)
viable: the skill menu fits the budget; full bodies load on demand and one language at a time.

---

## 3. Bilingual (EN/VI) rules — the careful part

**Convention: sibling locale files, English canonical.**

1. **Canonical = English.** `SKILL.md` and `catalog/<slug>/README.md` are the source of truth
   and hold the frontmatter / framework mappings (machine-discoverable, standard-compatible).
2. **Translation = `*.vi.md` sibling.** `SKILL.vi.md`, `README.vi.md`. The `.vi` infix before
   `.md` is the locale marker. Add more locales the same way (`.fr.md`, …) if ever needed.
3. **One language per load.** A reader/agent loads exactly one locale file, never both — so
   Vietnamese never inflates an English run's token budget, and vice-versa. This is the whole
   reason for sibling files over a single dual-language document.
4. **Frontmatter is not duplicated.** `SKILL.vi.md` may carry a minimal header
   (`name`, `lang: vi`) but the authoritative frontmatter (tags, mappings, version) lives only
   in the canonical `SKILL.md`. Tooling reads frontmatter from the canonical file.
5. **`languages: [en, vi]`** in the canonical frontmatter declares which locales exist, so the
   index/loader knows a translation is available without statting the filesystem.
6. **Switcher line.** Every localized doc starts with a one-line language switcher linking to
   its sibling(s), e.g. `**Languages:** English · [Tiếng Việt](README.vi.md)`.
7. **Fallback.** If a requested locale file is missing, the loader falls back to the canonical
   English file (never errors). Missing translations degrade gracefully.
8. **Technical terms stay English.** Keep established terms (SQL injection, payload, prepared
   statement, header) in English within Vietnamese prose; translate the explanation, not the
   keyword. This keeps `tags`/search working across languages.

### Resolver convention
Given a canonical path and a target locale, the localized path is mechanical:

```python
# canonical "en" is the bare name; any other locale inserts ".<locale>" before ".md"
def localized_path(canonical_md: str, locale: str = "en") -> str:
    if locale == "en":
        return canonical_md
    stem, dot, ext = canonical_md.rpartition(".")   # ("…/README", ".", "md")
    return f"{stem}.{locale}.{ext}"                 # "…/README.vi.md"
# Loader: try localized_path(p, locale); if absent, use p (English fallback).
```

This belongs in the `i18n/` pillar when it grows code; until then the rule above is the spec.

---

## 4. Tool-runner layer (hackingtool blueprint, future)

When SecForge adds *executable* tools (beyond the safe `http_get`/`note_finding`), follow
hackingtool's shape, mapped onto our safety model:

- **Categories** mirror the dictionary groups (Injection, Client-side, Auth, Server-side, APIs,
  Recon, …) rather than hackingtool's 20 offensive categories verbatim.
- Each tool: `TITLE`, `DESCRIPTION`, `INSTALL`, `RUN`, `SUPPORTED_OS` — **plus** a mandatory
  `authorized_targets` check (our existing [tool safety gate](../ai_framework/tools/README.md)).
  No tool runs against a target outside `RunConfig.authorized_targets`.
- OS-aware install/visibility and a search/tag menu, as in the reference.
- Tool `DESCRIPTION`/help strings are localized via the same `*.vi` convention.

This layer is **not built yet**; it is specified here so it lands consistently when it is.

---

## 5. How it plugs into the existing pillars

- **`ai_framework/skills/`** — home of `SKILL.md` folders; a thin loader emits frontmatter
  summaries for the system prompt and loads bodies on demand (see [skills/README](../ai_framework/skills/README.md)).
- **`vuln_search/catalog/`** — the dictionary; each card links to its skill + deep note, and now
  ships EN + VI.
- **`i18n/`** — owns the locale resolver (§3) and the active-locale setting for a run; the agent
  loads skill/catalog content in the run's locale, English-fallback.
- **`headroom/`** — one language per load keeps the budget honest; summaries are localized too.
- **Safety** — knowledge and tools are for **authorized testing only**; locale never changes the
  `authorized_targets` gate.

---

## 6. Adoption plan

1. ✅ Convention defined (this doc) + `SKILL_TEMPLATE.md` + i18n resolver spec.
2. ✅ Seed: 3 dictionary cards bilingual (SQLi/XSS/SSRF); 1 example skill (`SKILL.md` + `SKILL.vi.md`).
3. ⬜ Backfill `README.vi.md` for the remaining 26 catalog cards as their EN prose is completed.
4. ⬜ Author SKILL.md folders per technique (start with the OWASP Top-10-mapped classes).
5. ⬜ Implement the `i18n/` resolver + an `index.json` builder over skills (progressive scan).
6. ⬜ (Later) the hackingtool-style tool-runner with the safety gate.
