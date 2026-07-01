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
- **Recommend or generate hardening** — produce a prioritized report, and optionally draft
  the fix (input validation, output encoding, headers, config changes).
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

The static scan is the always-available offline path; the same loop in
[`ai_framework`](../ai_framework/README.md) (via `backend.RunService`) is the deeper, dynamic
complement. Served by the backend at `POST /defense/review`.

**Status:** implemented — static signature reviewer with secure-guidance mapping + re-check,
with tests (`tests/test_defense.py`).
