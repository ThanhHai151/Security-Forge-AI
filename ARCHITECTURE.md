# SecForge architecture, runtime status, and delivery plan

**Review date:** 2026-07-12
**Status:** supervised security-research prototype; not a production red-team platform.

> **Remediation update — 2026-07-15.** The P0 table in §4 has been worked through. All seven P0
> items are now addressed in code and covered by regression tests (`tests/test_p0_security_fixes.py`),
> then adversarially re-reviewed and hardened (`tests/test_phase2_fixes.py`). Summary:
>
> | P0 | Status | Where |
> |---|---|---|
> | Finding verifier replays arbitrary verbs | **fixed** | `agent/verify.py` — read-only method allow-list, RoE `prohibit` gate, limiter, audit |
> | Browser executes state-changing JS | **fixed** | `tools/browser.py` — method-gated subrequests + `service_workers="block"`; reclassified active-enumeration |
> | Prompt/model egress of untrusted text | **fixed** | `agent/system.py` fence+redact (delimiter-injection-safe) across all 6 backends; `local_only` mode |
> | Control-plane auth / CSRF | **fixed** | `backend/app.py` — content-type + `X-SecForge-Client` on mutating verbs (token clients exempt) |
> | Frontend XSS | *pre-existing; not in this pass* | tracked (P2 #33) |
> | Vite `/@fs` exposure | *pre-existing; not in this pass* | tracked (P2 #33) |
> | Locale traversal | **fixed** | `i18n/loader.py` allow-list; `../ai_accounts` blocked |
> | Provider SSRF / redirect / rebinding | **fixed** | new `harness/netguard.py` resolve-pin-and-gate egress guard; external-CLI path resolve-validated |
> | Durable-state races | **fixed** | `service.py` atomic approval CAS; sticky stop; boot-time campaign reconcile |
>
> Residuals kept as documented, lower-severity items: loopback is reachable by default (local-lab
> design choice); the external-CLI egress guard is pre-flight resolution, not socket pinning (a
> narrow TOCTOU remains because the binary re-resolves); WebSocket data frames and any
> caller-injected `ctx.renderer` are outside the browser method-gate; approval expiry trusts the
> wall clock. Full gap inventory and roadmap: `docs/AGENT_REVIEW_2026-07-15.md`.

This document describes the code that is present today, the trust boundaries that matter,
and the work required before enabling autonomous target traffic. It is deliberately more
conservative than the product vision: a feature is not a security control until it is
enforced at the final execution boundary and covered by an integration test.

## 1. What runs today

The normal development topology was smoke-tested successfully:

```text
Browser ──HTTP/JSON──> Vite console :61020 ──/api proxy──> Python API :61021
                                             │
                                             ├── knowledge_base / vuln_search / defense
                                             ├── supervisor (network-free advisory plan)
                                             ├── optional agent loop and tools
                                             ├── router/model providers (optional egress)
                                             └── JSON/JSONL stores, notebooks, evidence, findings
```

Commands:

```bash
SECFORGE_API_PORT=61021 ./.venv/bin/python -m backend.app
cd frontend && npm run dev -- --host 127.0.0.1 --port 61020
```

The API and Vite proxy returned 200 for `/accounts`, `/kb`, `/taxonomy`, `/models`,
`/evidence/verify`, `/i18n/en`, `/archetypes`, `/notebooks`, `/findings`, `/assets`,
`/api/accounts`, `/api/kb`, and `/api/taxonomy`. No target was contacted. Processes were
stopped after the check.

### Runtime modes

1. **Supervisor/advisory (default):** classifies an engagement, ranks the taxonomy,
   expands skills into staged questions, and produces a human-reviewed briefing. It does
   not send requests to a target.
2. **Legacy autonomous loop (opt-in):** enabled by `SECFORGE_ENABLE_AUTONOMOUS=1` and a
   typed rules-of-engagement (RoE). It can call HTTP, external CLI, and browser tools.
   It must remain disabled in shared or production environments until the P0 issues below
   are fixed and an isolated worker is mandatory.
3. **Defense/research:** static and dependency scans, KB/CVE lookups, and hardening advice.
   Online lookups are opt-in and can disclose target metadata to external services.

## 2. Components and data flow

- `frontend/`: React/Vite single-page console (Knowledge Base, Vuln Search, Agent,
  Defense, Router, notebooks and findings). `frontend/src/lib/markdown.js` renders Markdown.
- `backend/app.py`: `ThreadingHTTPServer` JSON API, request parsing, loopback Host/Origin
  checks, optional `SECFORGE_API_TOKEN`, and routing to services.
- `backend/service.py`: run/campaign lifecycle, approvals, findings, evidence and stores.
- `ai_framework/harness/`: typed RoE, scope/action policy, phases, limiters and vendor
  adapters. `supervisor/` is the safe planning path; `agent/` is the legacy executor.
- `ai_framework/tools/`: HTTP sessions, browser, external commands, research and
  evidence-producing actions.
- `ai_framework/router/` and `ai_framework/models/`: account pool, OAuth flows and
  OpenAI/Anthropic-compatible providers.
- `skills/`, `vuln_search/catalog/`, `knowledge_base/`: local security knowledge. The
  repository currently contains 60 Markdown files (31 localized documents), 32 registered
  skills, 29 taxonomy techniques across six categories, and 16 defense signatures covering
  11 vulnerability classes. The README's “~278 notes” claim is stale.
- `defense/`: code, dependency and optional online vulnerability scanning.
- `i18n/`: locale JSON loading and UI strings (`en` and `vi`).

Persistent data is currently spread across `ai_accounts.json`, `memory_store.jsonl`,
`findings_store.jsonl`, `runs_store/`, `notebook_store/`, and raw-log/assets stores. These
files can contain credentials, target data, prompts, and evidence; they are not a secure
multi-user data plane.

## 3. Current controls (implemented, but verify at deployment)

- Default loopback binding and Host/Origin checks; bearer token support when
  `SECFORGE_API_TOKEN` is configured.
- RoE target scope, exclusions, time window, action classification, approvals, pacing and
  per-run limits in the harness; supervisor path fails closed without authorization.
- Redirect handling and scope checks in the main run-loop HTTP path; external tools are
  disabled unless explicitly enabled.
- Redaction before most persistence, encrypted account-store support, and a hash-chained
  evidence ledger with `/evidence/verify`.
- Human review for supervisor notebook ingest and defense recommendations; no automatic
  source-code changes.

These controls do not establish isolation, authentication, tamper resistance, or safe
model egress by themselves. The host running a copied briefing must enforce the same policy.

## 4. Security review: issues that must be tracked

### P0 — block autonomous use

| Area | Evidence in current code | Required outcome |
|---|---|---|
| Finding verifier | `ai_framework/agent/verify.py` replays arbitrary method/headers/body after only URL scope checking. A local probe caused a `DELETE` during finding verification. | Reuse the action policy, approval and limiter for replay; allow only an explicit safe method set; test every verb. |
| Browser execution | `browser.py` route gate checks host but permits page JavaScript POST/DELETE; `browser_render` is classified passive. | Run browsers in an isolated worker through an egress proxy; gate navigation, subresources and state-changing requests. |
| Prompt/model egress | Raw tool logs and tool arguments enter OpenAI/Anthropic messages; persisted memory is inserted into system prompts. | Treat all target/tool text as untrusted; delimit/taint it, prevent instruction execution, redact before provider egress, and support local-only mode. OWASP describes this as excessive agency/prompt-injection risk ([OWASP Agentic Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)). |
| Control-plane auth | Loopback requests are accepted without a token by default; local processes can read/mutate accounts and approvals. | Require authenticated sessions even on loopback; add RBAC, CSRF protection, exact Origin/Content-Type checks and audit events. |
| Frontend XSS | Marked HTML reaches `dangerouslySetInnerHTML` without sanitization. | Sanitize with a reviewed policy (for example DOMPurify), add CSP, and test hostile Markdown. OWASP recommends sanitization and CSP ([XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)). |
| Vite file exposure | `server.fs.allow: [".."]` exposed `ai_accounts.json` and run transcripts through `/@fs/`. | Allow only catalog/docs roots; deny stores; bind to loopback and test `/@fs` disclosure. |
| Locale traversal | `/i18n/{locale}` accepts `../ai_accounts` and disclosed account JSON keys. | Allowlist locale IDs (`en`, `vi`) and never map URL input to arbitrary files. |
| Provider SSRF | Initial provider URL validation is bypassed by redirects/DNS rebinding; router accounts accept `file://` and arbitrary base URLs. | Centralize an `http/https` URL policy, disable/revalidate redirects, resolve and pin all A/AAAA addresses, and define private-network policy. See [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html). |
| Durable state races | Per-call evidence locks do not protect concurrent writers; campaign continuation and approval are check-then-act. | Use SQLite/transactional queue or shared file locks, atomic state transitions, idempotency keys and signed/externally witnessed evidence. |

### P1 — required for a professional engagement platform

- Make every runtime store atomic, mode `0600`, encrypted where appropriate, redacted
  (including notebooks), retained and access-audited. Current files were observed as `0664`.
- Add global (engagement-wide) RPS/concurrency/auth-attempt budgets, request and subprocess
  timeouts, output-size caps, cancellation, and a sandbox with deny-by-default egress.
- Ignore ambient `HTTP_PROXY`/`HTTPS_PROXY` unless explicitly configured; bind credentials
  to exact provider origins instead of a global Authorization header.
- Expire OAuth sessions, enforce PKCE/state and poll limits, validate callback/resource URLs,
  and write token files with `0600`.
- Bound request bodies and `step_budget`/phase counts; rate-limit the `ThreadingHTTPServer`;
  stream/rotate JSONL stores; enforce data-retention settings.
- Replace range-string dependency parsing with lockfile/resolver-aware SCA and emit an SBOM.
  The current scanner reports false positives from `>=`/`^` ranges and has no baseline/dataflow.
- Add authenticated-session/API contract tests, frontend tests, hostile-Markdown tests,
  browser/egress integration tests, race tests, coverage gates and security scanning in CI.
- Pin Python dependencies and GitHub Action SHAs, use least-privilege workflow permissions,
  add `SECURITY.md`/license, sign releases, and commit/review the current hardening. The
  worktree presently contains 98 changed/untracked entries, so these changes are not yet a
  reproducible release.
- Self-host fonts/assets and publish an explicit privacy warning for online OSV/CVE/model
  requests; do not send secrets or target content to third parties by default.

## 5. Comparison with `/home/thanhhai/Documents/TOOL/strix`

Strix is a broader execution framework: isolated Docker/container runtime, shell/browser/
exploit tools, proxy/Caido integration, multi-agent orchestration, SARIF/report output,
benchmarks, and release automation. SecForge currently has stronger typed RoE/supervisor
planning, a bilingual local KB, deterministic taxonomy/skills, and a compact HTTP console,
but lacks Strix's worker isolation, egress control, authenticated session model, tool
breadth, findings/report pipeline, and release discipline.

Borrow the capabilities, not unsafe defaults: Strix's container recipe uses floating Kali
packages and passwordless sudo, which is not an acceptable isolation baseline. SecForge
workers should use pinned minimal images, dropped privileges, read-only roots, seccomp/
AppArmor, explicit mounts, network policy and disposable credentials.

## 6. Professional red-team target state

### P0 delivery sequence

1. **Secure control plane:** mandatory auth/RBAC, CSRF, tenant/session isolation, API schema,
   audit log and safe defaults.
2. **Isolated execution plane:** queue jobs to disposable workers; egress proxy performs
   DNS/IP validation, redirect policy, rate limits and kill switch. The API never runs tools
   in its own process.
3. **Credential and model boundary:** opaque, origin-bound secret handles; DLP before logs,
   memory and model calls; local-only/provider allowlist and residency disclosure.
4. **Durable engagement state:** transactional campaign state machine, idempotent approvals,
   shared budgets, signed RoE, append-only evidence with external witness and retention policy.

### P1 capability sequence

Add specialist reconnaissance/web/API/cloud/container/IaC/identity agents; authenticated
session/role matrices; OAST and callback correlation; SAST/DAST/SCA/secrets/IaC scanners;
SARIF/JSON/PDF reports; finding deduplication, severity and remediation workflow; operator
kill switch; and a replayable evidence timeline. Every tool needs a manifest declaring
permissions, network effects, data classification, limits and rollback behavior.

### P2 product and assurance sequence

Add a Python lock/constraints file, SBOM and signed provenance; pinned CI actions; coverage
and fuzz/race gates; benchmark fixtures and safe-target end-to-end tests; SSO/RBAC/audit
export; backup/restore and retention controls; and documented threat model, disclosure
process and incident runbook. Plan assessments against NIST SP 800-115 ([Technical Guide to
Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)),
OWASP ASVS 5.0 ([OWASP ASVS](https://github.com/OWASP/ASVS)), and NIST SSDF
([SP 800-218](https://csrc.nist.gov/projects/ssdf)).

## 7. Verification checklist

Before each release run:

```bash
./.venv/bin/pytest
./.venv/bin/ruff check .
./.venv/bin/mypy backend ai_framework defense i18n knowledge_base vuln_search
cd frontend && npm ci && npm run build && npm audit
git diff --check
```

The last project audit recorded 383 passing tests and one optional skip, clean Ruff/Mypy,
successful frontend build, and zero npm audit findings. It also recorded Bandit's dynamic
URL warnings, Semgrep's unsanitized-HTML findings, environment-only `pip-audit` findings
in the local pip tool, and incomplete frontend/security CI. These are evidence for the
roadmap, not a claim of “100% complete”.

## 8. Operational boundary

Use only on assets for which written authorization, scope, timing, rate limits, contacts,
data handling and stop conditions are recorded. Do not enable autonomous mode, browser
automation, external commands, provider accounts or online research on a live engagement
until every P0 control is implemented and independently tested. A professional red-team
operator remains responsible for authorization and impact; SecForge is an assistant, not
permission to attack a target.
