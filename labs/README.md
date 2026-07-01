# `labs/` — Sandboxed Practice Range (PortSwigger-style)

**Pillar 5.** Intentionally vulnerable targets to practise against — the
PortSwigger Web Security Academy model — so you can go read → practise → automate without
leaving the platform.

## Responsibilities

- **A catalog of labs**, one per technique, each mirroring a documented KB topic
  (SQLi login bypass, reflected XSS, IDOR/access-control, path traversal, …).
- **A registry** that discovers labs automatically.
- **A separate host** that serves them.
- **Per-lab reset** so you can retry from a clean state.
- **Link back** — each lab points to its [`knowledge_base`](../knowledge_base/README.md)
  note and [`skill`](../ai_framework/skills/README.md), closing the learning loop.

## Safety posture (important)

The labs are deliberately vulnerable, so the skeleton bakes in containment:

- **Simulated, not real.** Each lab emulates its bug against an **in-memory fake
  database / fake filesystem**. No lab runs real OS commands, executes real SQL on your
  data, or makes real outbound requests from your machine.
- **Localhost only.** The labs host binds to `127.0.0.1`.
- **Separate port & process.** It runs apart from the main console, so vulnerable code is
  never mixed into the platform itself.
- **Disabled by default.** Turned on explicitly via config.

This teaches the vulnerability without opening a real hole on the host.

## Connects to

- [`../knowledge_base/`](../knowledge_base/README.md) & [`../ai_framework/skills/`](../ai_framework/skills/README.md) — each lab links to the matching note/skill.
- [`../ai_framework/`](../ai_framework/README.md) — the agent can be pointed at a lab as a
  safe, authorized target for end-to-end practice.
- [`../backend/`](../backend/README.md) — lists/launches labs; the "Labs" tab links here.

## Implementation

- [`base.py`](base.py) — transport-agnostic `Lab` protocol + `LabRequest`/`LabResponse`, so a
  lab is exercised identically by unit tests and the server.
- [`builtin.py`](builtin.py) — `sqli-login-bypass` (a quote-aware WHERE-clause evaluator over a
  fake user table — `administrator'--` really bypasses auth), `reflected-xss`, `idor`.
- [`registry.py`](registry.py) — discovers labs, dispatches requests, per-lab reset.
- [`server.py`](server.py) — localhost-only, separate port, **disabled by default**
  (`SECFORGE_LABS_ENABLED=1` or `make labs`); refuses to start otherwise.

The backend lists labs (metadata only) at `GET /labs`; the vulnerable server is a separate,
opt-in process so its code never mixes into the console.

**Status:** implemented — three sandboxed labs + registry + opt-in localhost server, with tests
(`tests/test_labs.py`).
