# `defense/` — Protect & Harden Any Web Project

**Pillar 4.** The defensive counterpart to the pentest framework: point SecForge at a web
codebase (or a running app you own) and have it find weak spots and propose concrete
hardening. It reuses the same brain as the offense side.

## Responsibilities

- **Review a target project** — scan source/config for the vulnerability classes
  catalogued in the [`knowledge_base`](../knowledge_base/README.md) (injection, access
  control, auth, SSRF, deserialization, …).
- **Map findings to fixes** — for each weakness, surface the relevant **secure-
  implementation** guidance. The KB notes already contain "Secure Implementation" and
  "Defense Checklist" sections, so one knowledge base serves both attack and defense.
- **Recommend hardening** — produce a prioritized report where each finding carries the
  concrete secure-implementation guidance for its class (input validation, output encoding,
  headers, config changes). Guidance is surfaced, not auto-applied.
- **Scan dependencies (SCA)** — inventory the project's packages and flag those with published
  advisories, with the fixed version to upgrade to.
- **Re-check** — confirm a recommended change addresses the finding.

## Why it shares the AI framework

Defense is the same loop with an inverted objective ("where could someone get in, and how
do we close it?"). So it reuses:

- [`../ai_framework/agent/`](../ai_framework/agent/README.md) — the reasoning loop.
- [`../ai_framework/skills/`](../ai_framework/skills/README.md) — which already carry
  secure-implementation notes.
- [`../ai_framework/models/`](../ai_framework/models/README.md) — the reasoning backend.
- [`../vuln_search/`](../vuln_search/README.md) — to identify what to look for.

## Connects to

- [`../frontend/`](../frontend/README.md) — the "Defense" tab (submit a project, read the
  report).
- [`../backend/`](../backend/README.md) — the defense API endpoints.

## Scope & safety

For projects **you own or are authorized to assess**. Read-only by default; any generated
fix is a proposal for you to review, not an automatic change.

## Implementation

- [`signatures.py`](signatures.py) — high-signal code-pattern `Signature`s, each tied to a
  catalog **slug** so a match pulls that class's "Defenses" guidance from the knowledge base.
  Adding a `Signature` covers a new class (the extension point).
- [`review.py`](review.py) — `review_path()` walks a project read-only, applies the
  signatures, and returns a severity-ranked `DefenseReport` whose findings each carry secure
  guidance; `recheck()` confirms a finding still reproduces (the "Re-check" step).
- [`deps.py`](deps.py) — **SCA**: `parse_dependencies()` reads a project's manifests/lockfiles
  (`requirements.txt`, `pyproject.toml`, `package.json`, `package-lock.json`) and
  `scan_dependencies()` flags packages with published advisories, with the fixed version to
  upgrade to. The advisory source is injectable (default: OSV.dev, opt-in-online) and degrades
  to an inventory-only report offline.

### Static, then dynamic (the "same brain" bridge)

The static scan + SCA are the always-available offline path. `RunService.defense_autopilot()`
(served at `POST /defense/scan`) returns that assessment **and**, when you pass `serve_url` for
the project's running instance, launches an **autopilot pentest** (the offense-side
[`ai_framework`](../ai_framework/README.md) loop) against it — so defense can *review the code
and attack the running app*, then guide the fix. Code findings carry secure guidance inline;
the live campaign's findings are polled like any other campaign.

- `POST /defense/review` — static code signatures only (unchanged, backward compatible).
- `POST /defense/scan` — code signatures + SCA + optional live attack (`serve_url`).

**Status:** implemented — static signature reviewer + SCA + secure-guidance mapping + re-check,
with an optional dynamic attack bridge; tests in `tests/test_defense.py`, `tests/test_deps.py`,
`tests/test_backend_pillars.py`.
