# SecForge Agent Codebase — Gap & Roadmap Review

_Review date: 2026-07-15 · Method: 11-agent deep read (6 module readers + 4 cross-cutting lenses + synthesis) over `ai_framework/agent/`, `harness/`, `supervisor/`, `tools/` and their coupling into `backend/`._

## Executive summary

The SecForge agent runtime is a well-architected demo-grade system whose headline mechanic genuinely works — log-driven planning truly feeds forward and steers the next act (loop.py:203,218,301-302; system.py:31-41), backends sit behind a clean two-method Protocol, the harness control-plane enforces a deterministic deny-before-allow RoE policy at the ToolRegistry.execute boundary (not just in prompt text), and the tool layer is safe-by-default (shell=False argv, host-execution opt-in, redirect scope re-checks). What blocks safe use is that the autonomous engine's core safety promises are not yet enforced in code: the only thing standing between six still-open P0s and live target traffic is the SECFORGE_ENABLE_AUTONOMOUS flag. Scope enforcement is purely lexical (no DNS resolution/IP pinning, encoded and private/metadata IPs pass — verified empirically), the finding verifier replays arbitrary HTTP verbs (DELETE/PUT/POST) entirely outside the policy/limiter/audit/approval path and slips the hold gate under a non-mutating note_finding, browser_render runs JS-executing Chromium under a passive-recon disposition with a host-only route gate, untrusted tool output/memory/model-plan reach the provider with no taint boundary or redaction, approve_action is a check-then-act race that can double-execute a destructive call, and /i18n path traversal discloses the account store. Compounding this, the loop is resilient to bad tools but fragile to a flaky model (unguarded act/plan, no retry/backoff/timeout, the documented `error` outcome never emitted), Headroom and planning don't compose (plan() gets the full un-fitted transcript and predictably overflows on long runs), and durability is aspirational (checkpoints are written but nothing resumes them; a mid-phase crash bricks a campaign in `running` and loses held approvals). The good news: the coupling is clean and injectable, so nearly every fix is local to loop.py/system.py/service.py plus the relevant backend/store, and centralizing all egress behind one resolve-pin-and-gate proxy closes most P0/P1 SSRF gaps at once.

## What already works well (do not rebuild)

- Log-driven planning is real, not vaporware: plan() runs after the turn is committed so it sees fresh logs, the plan is stored on the Turn, read back next iteration, and folded into the next act system prompt (loop.py:203,218,301-302; system.py:31-41) — the full feed-forward loop closes correctly and every backend implements it.
- Layered per-call safety gates in the correct, well-documented order: mutating-hold-before-guardrail-before-anti-loop so a held call stays re-proposable and is not counted as failure (loop.py:235-267).
- Clean backend abstraction: a two-method act/plan Protocol (models/base.py:46) makes loop code identical across offline/anthropic/anthropic-compat/router, and the offline heuristic backend makes the whole loop deterministically testable with no network.
- The harness control plane is the strongest, most professional module: typed operator-owned RoE with pydantic validation, deterministic deny-before-allow scope policy, fail-closed per-action evaluation, and — critically — enforcement in code at the ToolRegistry.execute boundary (tools/base.py:150) with a test proving off-scope rejection even when the legacy allow-list would permit it.
- Tool layer is carefully written and safe-by-default: one Tool protocol, one ToolContext safety surface, two scope choke points every network tool provably calls, argv-from-template with shell=False and hard-rejected extra_args (closes command injection), host execution refused unless explicitly opted in, and a ScopedRedirectHandler that re-checks scope on every redirect hop.
- The safety triad's opsec.py (Pacer) and guardrails.py are exemplary: tiny, pure, fully injected (clock/sleep/RNG), opt-in, and unit-tested; the mutating-vs-idempotent guardrail leash is real and verified.
- FindingVerifier's verification LOGIC is genuinely good: it refuses to call bare reachability a vulnerability, requires a differentiating expect marker/status, treats 4xx/5xx as real results, and degrades transport errors to unverified instead of crashing (the danger is only its unguarded egress, not its judgment).
- Per-file atomic durability (tmp+os.replace) and error-tolerant list summaries in the campaign/run stores; the escalate-only coverage rank in derive_coverage is a nice invariant.
- The advisory Supervisor path is cleanly isolated from the executor (zero imports of agent/tools/models/router/backend, verified) with a good progressive-disclosure briefing and a store-enforced human-in-the-loop invariant (ingest can never reach 'confirmed').
- Offline pentest kit (JWT decode/alg-none/crack/forge/verify, encode/decode) is complete and genuinely useful with no network side effects.
- ARCHITECTURE.md is honest: it self-flags its own stale README count and correctly labels the P0/P1 items as still-open rather than fixed.

## Prioritized gaps

35 findings, ranked. Severity: **P0** blocks safe autonomous use / is a correctness bug · **P1** needed for a professional platform · **P2** polish. Effort: S/M/L.

### P0 findings

#### 1. Scope enforcement is purely lexical — no DNS resolution or IP pinning; encoded and private/metadata IPs pass the hard-deny (SSRF / DNS-rebinding)
- **Severity/Effort/Module:** P0 · L · `harness + tools + models`
- **Why it matters:** This is the foundational egress-safety hole and it applies to EVERY network path (tools, verifier, browser, provider base_urls). Verified empirically that _is_hard_denied returns False for integer (2852039166), hex (0xA9FEA9FE), IPv4-mapped-IPv6 ([::ffff:169.254.169.254]) encodings of 169.254.169.254 and for 127.0.0.1/10.1.2.3/192.168.0.5/fd00::1/::1. An in-scope hostname whose DNS points at (or rebinds to) metadata/internal space passes the gate and urllib re-resolves and connects. For an autonomous tool pointed at hostile targets this defeats the module's core SSRF claim, and the render layer even instructs the model to 'revalidate DNS/redirect destinations' with no code behind it.
- **What to add:** Add a single resolve-and-pin egress guard invoked at CONNECT time, not on the request string: (a) normalize integer/hex/octal/IPv4-mapped hosts to canonical IPs before the hard-deny check; (b) resolve all A/AAAA and reject any loopback/link-local/private/ULA/CGNAT/metadata address unless a new RoE flag allow_private_ranges (default False) authorizes it; (c) connect to the pinned validated IP with the original Host header via a custom resolver/connection hook so the name cannot rebind between check and connect; (d) apply the same guard on every redirect hop and to provider base_urls. Route all egress (tool session, verifier replay, browser subresources, provider client) through this one guard so scope becomes non-lexical everywhere at once.
- **Files:** `ai_framework/harness/policy.py`, `ai_framework/tools/session.py`, `ai_framework/models/openai_compat.py`, `ai_framework/harness/contracts.py`
- **Depends on:** none — but its egress-proxy form is the natural landing point for gaps #2, #3

#### 2. FindingVerifier replays an arbitrary HTTP verb outside the harness (no policy/approval/limiter/audit/pacer) and slips the hold gate under note_finding
- **Severity/Effort/Module:** P0 · M · `safety-verify + tools + loop`
- **Why it matters:** ARCHITECTURE P0, still fully present. verify() takes method/headers/body verbatim from the model-supplied repro and opens it directly through the run session after only a URL scope check, never calling enforce_tool_policy, the EngagementLimiter, the Pacer, or ctx.audit, and defining no safe-method allowlist. It is invoked from loop._record_finding on a note_finding call, which runtime.py classifies as evidence_capture (non-mutating), so the hold_mutating approval gate never fires. A single note_finding with repro={request:{method:'DELETE'},expect_status:200} fires a real DELETE even in campaign/hold mode and is rewarded status=reproduced/confidence=high — the exact incident the doc records. It also leaves no ledger entry, escaping incident reconstruction.
- **What to add:** Route the repro through ToolRegistry.execute by constructing a synthetic http_request ToolCall so enforce_tool_policy + EngagementLimiter.before/after + ctx.audit.record_tool + Pacer all apply; OR restrict replays to an explicit _SAFE_METHODS={GET,HEAD,OPTIONS} (reuse runtime._SAFE_METHODS) and return (False,'method X requires approval') otherwise. Add a repro branch to action_request_for_tool so an embedded state-changing request is classified. Serialize dict/list bodies to JSON with Content-Type. Emit an audit record (method/URL/status/redacted body) for every replay, verified or not.
- **Files:** `ai_framework/agent/verify.py`, `ai_framework/agent/loop.py`, `ai_framework/harness/runtime.py`, `tests/test_verify.py`
- **Depends on:** shares the egress-proxy destination of #1; the per-verb test is required regardless

#### 3. browser_render is classified passive_reconnaissance and its route gate checks host but not method; the injected renderer gets no scope callback
- **Severity/Effort/Module:** P0 · M · `tools + harness`
- **Why it matters:** ARCHITECTURE P0, unchanged. A JS-executing headless Chromium sits in the least-restrictive network gate; its per-request route handler validates only the URL host and calls route.continue_() regardless of method, so page JavaScript can issue POST/PUT/DELETE to in-scope endpoints under a recon disposition. The ctx.renderer injected-renderer branch is handed no scope validator at all, so a sandboxed renderer's subresources are entirely ungated.
- **What to add:** Classify browser_render as active_enumeration (or a new interactive ActionClass mapping to require_approval) in runtime.action_request_for_tool. In the route gate, abort any non-safe (non-GET/HEAD/OPTIONS) method unless state-change is RoE-authorized and approved. Extend the ctx.renderer contract so an injected renderer must call back a scope+method validator before each navigation/subresource. Ideally run the browser behind the #1 egress proxy so enforcement is independent of the tool.
- **Files:** `ai_framework/tools/browser.py`, `ai_framework/harness/runtime.py`

#### 4. Untrusted tool output / recalled memory / model plan reach the provider with no taint boundary, redaction, or local-only mode
- **Severity/Effort/Module:** P0 · L · `loop-core + models`
- **Why it matters:** ARCHITECTURE P0, live in loop-core. Raw tool_result logs are sent verbatim to the provider on every act AND plan call by all wire backends; recalled memory bodies (raw tool logs/args) are injected straight into the system prompt via with_memory; and with_plan folds the model's own plan text — derived from untrusted logs — back into the system prompt as a standing 'execute the next step of it' instruction, the classic excessive-agency amplifier. redact_* runs only on API output and disk persistence, never before backend.act/plan. This is textbook prompt-injection exposure for an autonomous agent.
- **What to add:** Introduce a taint boundary: wrap all target-derived text (tool_result logs, recalled memory bodies, and the plan) in explicit untrusted-data delimiters with a standing system rule that content inside is data, never instructions. Add a scrub/redact pass on transcript + memory + plan text BEFORE it is handed to backend.act/plan (not only before disk). Add a local-only / provider-allowlist config flag that refuses remote egress when set. Feed with_plan output through the same scrubber.
- **Files:** `ai_framework/agent/loop.py`, `ai_framework/agent/system.py`, `ai_framework/models/anthropic_backend.py`, `ai_framework/models/anthropic_compat.py`, `ai_framework/models/openai_compat.py`

#### 5. approve_action is a check-then-act race — a held state-changing tool can execute twice
- **Severity/Effort/Module:** P0 · S · `campaign-persist (backend/service.py)`
- **Why it matters:** ARCHITECTURE P0, still present. approve_action reads approval.status==pending, calls registry.execute() on the mutating tool, then sets status=approved, with NO lock across the steps. Two concurrent POSTs for the same approval_id (double-click, retry, two operators) both pass the pending check and both execute the destructive call, defeating the single-approval-single-execution safety promise.
- **What to add:** Under self._lock (or a per-campaign lock), re-load the campaign, verify approval.status==pending, flip it to an in-progress sentinel and PERSIST before releasing the lock and executing (compare-and-set); add an idempotency key so a retried approval id is a no-op. Persist the status flip so a crash mid-execute cannot re-open the approval. Add a threaded test firing two approve_action calls asserting exactly one registry.execute via a counting stub tool.
- **Files:** `backend/service.py`, `tests/test_campaign.py`
- **Depends on:** shares the locking pattern with #11

#### 6. /i18n/{locale} path traversal discloses arbitrary parent-directory *.json including the account store
- **Severity/Effort/Module:** P0 · S · `i18n + backend`
- **Why it matters:** ARCHITECTURE P0, still open — no locale allowlist exists despite LOCALES=('en','vi'). load_strings builds I18N_DIR / f'{locale}.json' with no validation; the route uses removeprefix with no unquote/allowlist. Verified: load_strings('../ai_accounts') returns the account-store JSON keys, disclosable over the token-less loopback API with curl --path-as-is.
- **What to add:** Reject any locale not in the ('en','vi') allowlist in load_strings, again in pillars.i18n, and again at the route, returning the default locale for anything else; never map URL input to a filesystem path. Add a test asserting '../ai_accounts' and encoded traversal are refused.
- **Files:** `i18n/loader.py`, `backend/pillars.py`, `backend/app.py`

#### 7. Control-plane auth is only partially fixed: token-less by default, Origin checked only when present, no CSRF/Content-Type/RBAC/audit
- **Severity/Effort/Module:** P0 · M · `backend/app.py`
- **Why it matters:** ARCHITECTURE P0, partially fixed. Loopback binding, a Host-header loopback check, and an optional SECFORGE_API_TOKEN exist, but by default no token is configured, so any local process (or other local user) can read/mutate accounts, approvals, and start autonomous runs on loopback. The Origin check only fires when an Origin header is present, there is no Content-Type enforcement, no CSRF token, no RBAC, and no audit events.
- **What to add:** Require an authenticated session even on loopback (generate a token on first run if unset); enforce exact Content-Type: application/json on state-changing verbs; treat a missing Origin on POST/PATCH/DELETE as reject (or require a CSRF token); add minimal RBAC; emit audit events for account/approval/run mutations.
- **Files:** `backend/app.py`

### P1 findings

#### 8. No model-call resilience: act/plan unguarded, no retry/backoff/timeout, and the documented `error` outcome is never emitted by the loop
- **Severity/Effort/Module:** P1 · M · `loop-core + models`
- **Why it matters:** The loop is resilient to bad tools (registry.execute degrades exceptions) but fragile to a flaky model — the opposite of what an unattended campaign needs. A single 429/5xx/network blip/expired token/hung request raises straight out of run_loop and aborts the whole run or campaign phase with zero retry. The Anthropic client is built with no timeout. run_loop never sets Run.outcome='error' (contracts.py:116 documents it), delegating all error handling to callers — and demo.py/tui.py don't wrap it, so they crash and lose the partial run.
- **What to add:** Wrap backend.act/backend.plan in bounded exponential backoff + jitter, distinguishing retryable (429/5xx/timeout/connection) from fatal (auth/schema) errors; on exhaustion set run.outcome='error'/run.error and break so the loop always terminates in a defined, checkpointed state regardless of caller. Set an explicit request timeout on the provider clients. Add a test with a backend whose act() raises, asserting outcome=='error' and the partial transcript is preserved.
- **Files:** `ai_framework/agent/loop.py`, `ai_framework/models/anthropic_backend.py`, `ai_framework/agent/contracts.py`, `tests/test_loop.py`
- **Depends on:** composes fatally with #9 — fix together

#### 9. plan() bypasses Headroom — it is sent the full un-fitted transcript and predictably overflows the context window on long runs
- **Severity/Effort/Module:** P1 · S · `loop-core`
- **Why it matters:** When Headroom is active, act() gets the fitted/compacted transcript but the next plan() call is passed run.transcript — the full, unbounded turn history (loop.py:302). On exactly the long runs Headroom exists for, plan() exceeds the window and the provider errors, which (combined with #8's no-retry) aborts the run. Half of every turn's LLM traffic silently defeats the operator's configured budget.
- **What to add:** Route plan() through the same fit(): reuse fitted.transcript/tools/memory computed for the act call (or call fit() again for the plan request) and append a second CompactionReport so the plan call is within budget and auditable.
- **Files:** `ai_framework/agent/loop.py`
- **Depends on:** pairs with #8

#### 10. No restart recovery or resume: a mid-phase crash bricks the campaign in 'running' and loses held approvals; 'replay' is aspirational
- **Severity/Effort/Module:** P1 · L · `campaign-persist`
- **Why it matters:** run_store's 'recoverable/replayable' docstring has no implementation — load() returns an inert Run and nothing re-drives run_loop. _run_phase writes status='running' before executing and there is no boot-time reconcile, while continue_campaign refuses status 'running', so a crashed campaign can never be resumed OR cleanly stopped. PendingApprovals accumulate only in memory and persist only at phase end, so a crash loses every mutating action the operator was meant to approve.
- **What to add:** Persist held approvals immediately inside on_hold. Add a boot-time reconcile that scans campaigns_store: any status=='running' with no live thread is marked 'interrupted' (and resumed from the last checkpointed turn or failed cleanly); let continue_campaign accept 'interrupted'. Implement an actual resume path that seeds run.transcript from a loaded checkpoint and re-enters run_loop, or explicitly downgrade the docstring. Add a crash-then-reload test.
- **Files:** `backend/service.py`, `ai_framework/agent/run_store.py`, `ai_framework/agent/campaign.py`, `tests/test_run_store.py`

#### 11. continue_campaign / stop_campaign check-then-act races; shared Campaign object mutated by worker while API model_dump() reads it unlocked
- **Severity/Effort/Module:** P1 · M · `campaign-persist`
- **Why it matters:** continue_campaign checks status then spawns a phase thread with no lock/status-flip, so two near-simultaneous continues start two worker threads mutating the same Campaign object (corrupting phase order/coverage, double-spending budget). stop_campaign's Stop can be silently overwritten if the phase finishes 'done' between the save and the coverage-fold. get_campaign calls campaign.model_dump() unlocked while the worker appends to pending_approvals/phases, risking 'list changed size during iteration' / torn snapshots.
- **What to add:** Under self._lock, re-check and atomically flip status to 'running' before spawning a phase (refuse the second caller). Treat 'stopped' as sticky: after a phase, re-load under the lock and never transition out of terminal 'stopped'; have _run_phase check cancel.is_set() before recomputing status. Deep-copy (model_copy(deep=True)) the campaign before model_dump in get_campaign, or serialize all campaign mutations through a single per-campaign lock. Add threaded tests for both races.
- **Files:** `backend/service.py`, `tests/test_campaign.py`
- **Depends on:** shares locking pattern with #5

#### 12. Approval tokens are membership-checked but never consumed or expired — 'approve once, replay forever'
- **Severity/Effort/Module:** P1 · M · `harness + backend`
- **Why it matters:** approval_token_for_call binds a token to (scope_digest, action_class, target, tool, arguments) but includes no nonce, approval id, step, or expiry; enforce_tool_policy only checks set membership and never removes it; service.approve_action adds it and never revokes it. Once any state-changing/credential/exploitation call is approved, an identical call can be re-executed unboundedly for the ctx lifetime.
- **What to add:** Make approvals single-use and time-bounded: include a per-approval nonce/approval-id and expiry (tie to approval_timeout_seconds) in the token; store granted approvals with a remaining-use count; have enforce_tool_policy consume (decrement/remove) the token on use; optionally bind to the specific ToolCall.id.
- **Files:** `ai_framework/harness/runtime.py`, `backend/service.py`

#### 13. No engagement-wide budgets/timeouts/output caps/cancellation; timeout-less semaphore can hang the worker; limiter state is in-memory and resets on restart
- **Severity/Effort/Module:** P1 · M · `harness/limits.py`
- **Why it matters:** EngagementLimiter caps RPS/concurrency/auth-attempts/body-size but has no total-request/subprocess cap, no request/subprocess timeout, no response/output-size cap, and no cancellation. before() acquires the semaphore with NO timeout then sleeps to pace while holding the slot, so one hung tool blocks all subsequent network actions indefinitely (self-DoS). State is per-limiter-instance and per-campaign, so a restart or crash-loop resets the whole-engagement rate/auth budget — bypassing it entirely. Also: step_budget/phase_step_budget/max_phases are unbounded ints validated straight from the token-less API body.
- **What to add:** Add max_total_requests/max_total_subprocesses/max_response_bytes and per-call+per-subprocess timeouts to the RoE and enforce in before()/after(); pace BEFORE acquiring the slot; use semaphore.acquire(timeout=...) and raise on exhaustion; add a cancel/kill-switch hook; persist limiter counters (campaign sidecar) and rehydrate on load. Add Field(ge=1, le=<sane max>) to step_budget, phase_step_budget, max_phases.
- **Files:** `ai_framework/harness/limits.py`, `ai_framework/harness/contracts.py`, `ai_framework/agent/contracts.py`, `ai_framework/agent/campaign.py`, `backend/service.py`
- **Depends on:** persistence overlaps with #10

#### 14. Two divergent action-classification systems that disagree; sqlmap under-classified as vulnerability_identification, not exploitation
- **Severity/Effort/Module:** P1 · M · `tools + harness`
- **Why it matters:** State-change is classified twice — tool_is_mutating (static flag/is_mutating_call, drives the campaign hold + guardrail leash) and action_request_for_tool (drives RoE policy) — and they already disagree (http_request is statically mutating=True yet runtime calls a bare GET passive_reconnaissance). The dangerous direction: sqlmap sits in _VULN_IDENTIFICATION_TOOLS, which forces approval only on production/critical/unknown assets, so on a non-production known-criticality asset at l2 autonomy sqlmap (active SQLi, data extraction, state change) runs with NO approval via the RoE path. Any new tool must be remembered in two files or is mis-gated.
- **What to add:** Have each Tool and each run_recon Preset declare one canonical ActionClass; derive both the campaign hold/guardrail leash and the RoE decision from it, deleting the hand-maintained name sets in runtime.py. Map sqlmap (and nuclei with intrusive/exploit tags) to ActionClass.exploitation (in _ALWAYS_APPROVAL). Add a contract test iterating the registry asserting both classifiers agree for every tool.
- **Files:** `ai_framework/harness/runtime.py`, `ai_framework/tools/base.py`, `ai_framework/tools/security.py`, `ai_framework/tools/external.py`

#### 15. Ingest CONFIRMED regex silently drops hyphenated technique names — a large share of canonical vuln-class confirmations are lost invisibly
- **Severity/Effort/Module:** P1 · S · `supervisor/ingest.py`
- **Why it matters:** _CONFIRMED_RE uses a lazy (.+?) name group followed by [-—] as separator, so for any hyphenated technique the quantifier stops at the first internal hyphen: 'CONFIRMED: Cross-Site Scripting — ...' parses technique='Cross', which taxonomy.match_text can't resolve, hitting `if not hits: continue` and discarding the confirmation. This covers XSS/SSRF/CSRF/SSTI/DOM-based/Host-header. Because the keyword fallback is skipped whenever any hyphen-free marker also appears, the loss is total and invisible — a professional platform cannot silently drop 'CONFIRMED: Cross-Site Scripting'.
- **What to add:** Require whitespace around the dash separator (\s+[-—]\s+) and make the name group greedy up to the optional [severity]; also accept ':' as a separator. When match_text returns multiple candidates prefer an exact-label match. Add a test table over Cross-Site Scripting/SSRF/CSRF/SSTI/DOM-based XSS/Host-header, each with and without a [severity] bracket, asserting the correct node is promoted.
- **Files:** `ai_framework/supervisor/ingest.py`, `tests/test_ingest.py`

#### 16. record_manual_action can DOWNGRADE a confirmed technique — duplicated coverage-upsert diverged from the escalate-only invariant
- **Severity/Effort/Module:** P1 · S · `campaign-persist`
- **Why it matters:** derive_coverage carefully enforces escalate-only ranking so status never downgrades, but record_manual_action re-implements the upsert and sets cur.status=(confirmed if ok else tried) UNCONDITIONALLY. A failed operator-approved action on a previously-confirmed technique silently wipes it to 'tried', destroying evidence of a real finding, and can stomp 'blocked'. The only test passes an empty coverage list so the downgrade path is never exercised.
- **What to add:** Extract the rank+upsert into ONE shared helper used by both derive_coverage and record_manual_action so the escalate-only invariant holds on both paths; return a sorted list to match. Add a test seeding a confirmed technique, applying a failed manual action, asserting it stays confirmed.
- **Files:** `ai_framework/agent/campaign.py`, `tests/test_campaign.py`

#### 17. Untrusted target content enters notebook state and the next briefing via unfenced ingest markers, and the keyword fallback over-promotes ruled-out techniques
- **Severity/Effort/Module:** P1 · M · `supervisor/ingest.py`
- **Why it matters:** ingest_output parses CONFIRMED:/NEW_FINDING_TYPE: markers from the whole pasted blob with no fence, so target text quoted by the agent can create custom nodes / promotions, and the extracted note/justification is echoed verbatim into the NEXT advise() briefing (a second-order prompt-injection path into model context — the same class ARCHITECTURE flags P0). Separately the keyword fallback promotes the single top-scoring technique from the whole transcript, so a technique explicitly ruled out ('checked for SQLi, found nothing') still gets promoted to 'unconfirmed', making the notebook untrustworthy in both directions.
- **What to add:** Require markers to appear only inside an explicit agent-authored fence (BEGIN_SECFORGE_MARKERS...END) and ignore marker lines outside it. When rendering notebook notes back into the briefing (_render_notebook_status), wrap all ingest-sourced note/justification/label text in a clearly-labelled untrusted-data block. Drop the silent fallback promotion; instead return keyword candidates as human-review suggestions and record promoted=[] when no valid marker is found.
- **Files:** `ai_framework/supervisor/ingest.py`, `ai_framework/supervisor/assemble.py`
- **Depends on:** builds on the #15 marker fix

#### 18. Runtime stores (findings/memory/runs/campaigns/assets/notebooks) are written with default umask, not 0600
- **Severity/Effort/Module:** P1 · S · `campaign-persist + notes/memory/notebook`
- **Why it matters:** ARCHITECTURE P1, still open. Only the account store and evidence ledger chmod 0600; every other durable store writes via write_text/open with no chmod, landing group/world-readable (observed 0664). Run transcripts, findings, memory, coverage, assets, and notebooks contain target data and near-secret material despite redaction — an inconsistency, not policy.
- **What to add:** Add a shared _atomic_write_0600 helper (tmp write -> chmod 0600 -> os.replace -> chmod 0600) and create parent dirs 0700; reuse it across campaign.py, run_store.py, assets.py, notes/store.py, memory/store.py, notebook/store.py to match accounts/ledger.
- **Files:** `ai_framework/agent/campaign.py`, `ai_framework/agent/run_store.py`, `ai_framework/agent/assets.py`, `ai_framework/notes/store.py`, `ai_framework/memory/store.py`, `ai_framework/notebook/store.py`

#### 19. Session egress hygiene: ambient HTTP(S)_PROXY silently honored, and set_auth installs a global Authorization header sent to every host and across redirects
- **Severity/Effort/Module:** P1 · M · `tools (session.py, auth.py)`
- **Why it matters:** Two ARCHITECTURE P1s. HttpSession._build_opener only adds a ProxyHandler when self.proxy is set; when empty, build_opener installs the default handler that reads getproxies() from the environment, so an ambient host proxy silently reroutes all tool traffic (egress/exfil/OPSEC surprise). SetAuthTool adds Authorization: Bearer <token> to opener.addheaders, which urllib attaches to every subsequent request regardless of host and across cross-origin redirects, disclosing the bearer token to all in-scope hosts.
- **What to add:** When proxy is empty, append ProxyHandler({}) so environment proxies are ignored; only honor an explicitly configured proxy and log the effective proxy at build. Store auth credentials keyed by origin and attach Authorization only when the request host matches; strip Authorization on cross-origin redirects; give set_auth an explicit origin/scope argument.
- **Files:** `ai_framework/tools/session.py`, `ai_framework/tools/auth.py`

#### 20. Evidence chain-of-custody is incomplete: findings don't link to ledger rows and the verifier replay is never audited
- **Severity/Effort/Module:** P1 · M · `notes + evidence + verify`
- **Why it matters:** The hash-chained ledger records every registry tool call, but the Finding record has no field pointing back to the ledger entry/call_id that produced it, so a status=reproduced/confidence=high finding has no auditable pointer to the proving request/response. Worse, the verifier replay that promotes findings to reproduced/high goes outside the registry and produces NO ledger entry, and the ledger stores only the truncated result.log, not raw request/response bytes. The platform's 'raw request/response' proof standard is not backed by an unbroken, finding-linked custody chain.
- **What to add:** Add an evidence_ref (ledger call_id/sequence list) to Finding and populate it in _record_finding from the producing tool call(s). Route the verifier replay through the audited path (or have verify() emit an audit record) so verification appears in the hash chain. Store enough of the raw request/response in the ledger payload to satisfy the proof standard.
- **Files:** `ai_framework/notes/contracts.py`, `ai_framework/agent/loop.py`, `ai_framework/agent/verify.py`, `ai_framework/evidence/ledger.py`
- **Depends on:** the verifier-audit half lands with #2

#### 21. No research / KB gap-filling trigger anywhere in the loop — the adaptive 'learn what you don't know' capability is absent (README claims it exists)
- **Severity/Effort/Module:** P1 · L · `loop-core + research`
- **Why it matters:** A complete adaptive agent should detect when observed target tech/behavior is outside its knowledge and pull reference material before acting. The loop README credits the loop with this, but there is no research import/call in loop.py; skills are injected only as a static catalog and pulled via load_skill only if the model remembers to call it. Nothing observes a result, notices an unknown framework/CVE/error, and gap-fills — the agent can only recombine what is already in context.
- **What to add:** Add a post-observation gap detector: when a tool result surfaces a technology/CVE/error the KB/skill catalog doesn't cover (or the model flags low confidence), auto-invoke retrieval (load_skill by matched slug, or an offline vuln_search KB lookup) and fold the result into the next act's system prompt through the same untrusted-data delimiting from #4. Wire archetype/vuln_search into the executor.
- **Files:** `ai_framework/agent/loop.py`, `ai_framework/research/`, `ai_framework/agent/system.py`
- **Depends on:** #4 (reuse the taint delimiter for injected reference text)

#### 22. Memory recall is not relevance-wired and does not scale; no lesson distillation
- **Severity/Effort/Module:** P1 · M · `memory + loop`
- **Why it matters:** recall is called with an EMPTY technique query, so its relevance key is always 0 and it degenerates to target-scoped recency top-K while being injected under a 'Relevant memory recalled' header — overstating reality. It also doesn't scale: recall() reads and json-parses the ENTIRE memory file every turn, and has_failed_attempt() re-reads the whole file once PER tool call, so a long campaign re-parses the growing corpus O(turns) times. MemoryKind.lesson is never written by the loop, so the agent's own experience never distils into a reusable lesson.
- **What to add:** Pass a real relevance query into recall (goal/last plan/last observation keywords or the tool about to run) and score technique/semantic match, not just recency. Load the JSONL once per turn (or keep an in-memory index / dedup set for has_failed_attempt) instead of re-reading per call. Have the loop distil an explicit lesson record on notable success/failure.
- **Files:** `ai_framework/memory/store.py`, `ai_framework/agent/loop.py`

#### 23. ToolContext.workspace is never wired, so ffuf/gobuster are advertised but dead; tool coverage badly trails the skill catalog
- **Severity/Effort/Module:** P1 · M · `tools + loop`
- **Why it matters:** external._require_confined_wordlist raises whenever a wordlist is present and ctx.workspace is empty, but loop.py builds ToolContext without ever setting workspace, so the two wordlist tools always fail through the real run path. More broadly the agent can READ 37 SKILL.md techniques but ACT through only 13 tools, so its action surface is far narrower than its knowledge surface and it is steered toward actions it cannot perform.
- **What to add:** Populate ToolContext.workspace from RunConfig (a per-run 0700 dir or RoE.evidence_directory), create it 0700, and ship a bundled wordlist inside it so ffuf/gobuster work — or drop them from the advertised set. Audit the skill catalog for techniques with no executing tool and either add tools or mark those skills advisory-only.
- **Files:** `ai_framework/agent/loop.py`, `ai_framework/tools/external.py`, `ai_framework/agent/contracts.py`

#### 24. project_path allows unbounded arbitrary-directory source scanning via the token-less advise endpoint
- **Severity/Effort/Module:** P1 · M · `supervisor`
- **Why it matters:** ctx.project_path is passed straight into detect_techniques/rank_files (Path(project_path).rglob('*')) with no confinement, reaching code unvalidated from the token-less loopback POST /supervisor/advise. A caller can point it at any readable directory; the returned context_block discloses matched file paths and the vuln-signal classes each triggers — a filesystem-enumeration primitive that pairs with the control-plane-auth gap (#7).
- **What to add:** Constrain project_path to an allowlisted workspace root (a configured SECFORGE_WORKSPACE or the engagement's evidence_directory); resolve and require it to be within that root, reject symlink escapes, and return a blocker in Advice rather than scanning when out of bounds.
- **Files:** `ai_framework/supervisor/contracts.py`, `ai_framework/supervisor/strategy.py`, `backend/service.py`
- **Depends on:** #7

### P2 findings

#### 25. JsonlAssetStore lacks parse-error tolerance, locking, dedup, and rotation — can crash the recon view and grows unbounded
- **Severity/Effort/Module:** P2 · S · `campaign-persist (assets.py)`
- **Why it matters:** Unlike list_campaigns/list_runs which tolerate parse errors, all() calls Asset.model_validate_json with no try/except and write() appends unlocked, so a concurrent reader hitting a partial last line raises and takes down summary()/for_target() and any route built on them. _record_assets writes every asset with no dedup and there is no rotation, so the same endpoint re-recorded each phase appends duplicate lines forever and by_kind counts inflate.
- **What to add:** Wrap per-line parsing in try/except (skip/log bad lines) to match sibling stores; take a threading.Lock / fcntl.flock around append+read. Dedup on (target,kind,value) at write time and add size-based rotation / a max-line cap; expose a de-duplicated total in summary(). Add a truncated-final-line test.
- **Files:** `ai_framework/agent/assets.py`, `ai_framework/agent/loop.py`, `tests/test_assets_coverage.py`
- **Depends on:** folds into the #18 shared-helper work

#### 26. Loop→campaign coverage contract is a brittle magic string ('held for manual approval') with no structured field
- **Severity/Effort/Module:** P2 · S · `campaign-persist + loop`
- **Why it matters:** derive_coverage detects held/blocked techniques by substring-matching the tool result LOG text against the exact phrase the loop writes; any wording change silently breaks blocked-coverage classification, and a target response echoing that phrase is misclassified as a held action. note_finding/record_asset detection is likewise coupled by string literal to tool names. The one test hardcodes the same magic string, locking in the coupling.
- **What to add:** Add a structured field to ToolResult (held: bool or a status enum) set when the loop holds a call; have derive_coverage read the flag instead of scraping log text. Centralize tool-name constants (NOTE_FINDING, RECORD_ASSET). Update the test to assert on the flag.
- **Files:** `ai_framework/agent/contracts.py`, `ai_framework/agent/loop.py`, `ai_framework/agent/campaign.py`, `tests/test_campaign.py`

#### 27. Autopilot stop condition rarely fires: made_progress counts merely-mentioned techniques
- **Severity/Effort/Module:** P2 · S · `campaign-persist + backend`
- **Why it matters:** made_progress is true if ANY new technique slug appears this phase, but derive_coverage stores techniques only NAMED in reasoning/next_plan as 'untried'. Because the model routinely mentions new attack-class keywords in planning text, new_techs is almost always non-empty, hardened_streak resets nearly every phase, is_hardened seldom triggers, and autopilot burns max_phases every time regardless of whether it exercised anything — undermining the headline no_new_findings_within_budget feature.
- **What to add:** Base progress on EXERCISED signal only — a new confirmed finding or a technique newly moved to tried/confirmed/blocked this phase (exclude untried-only mentions). Keep untried for planning steering but do not let it reset the streak. Add a test with a stub that names a new technique but exercises nothing, asserting the streak still increments.
- **Files:** `backend/service.py`, `ai_framework/agent/campaign.py`, `tests/test_campaign.py`

#### 28. Guardrail counts held-for-approval turns as no-progress and places no ceiling on successful state-changing actions
- **Severity/Effort/Module:** P2 · S · `safety-verify (guardrails) + loop`
- **Why it matters:** observe_turn is fed any(r.ok for r in results), but held calls produce ok=False synthetic results, so a phase whose only promising leads are state-changing keeps proposing all-held turns → every turn reads as no-progress → the guardrail can halt a phase that is correctly queuing actions for approval. Separately the guardrail is purely a failure breaker: a mutating tool that keeps SUCCEEDING is never throttled, so in the demo (guardrail with no RoE/limiter) the only ceiling on cumulative state change is step_budget.
- **What to add:** Track held-count separately and treat an all-held turn as progress-neutral when computing observe_turn. Add an optional max_mutating_actions to GuardrailConfig that counts successful mutating calls and halts when exceeded. Add a loop-level test wiring hold_mutating + guardrail asserting no false no-progress halt across N held turns.
- **Files:** `ai_framework/agent/loop.py`, `ai_framework/agent/guardrails.py`, `tests/test_guardrails.py`
- **Depends on:** benefits from the #26 held flag

#### 29. Cancellation is coarse and pacing sleeps block it; verifier and plan sleeps ignore the Stop button
- **Severity/Effort/Module:** P2 · S · `loop-core + opsec`
- **Why it matters:** The cancel Event is checked once per iteration at the top of the loop, but a turn can run multiple slow tool calls, OPSEC pacing sleeps, and two LLM calls, during which Stop has no effect. Pacer.wait sleeps synchronously on the loop thread, so cancellation latency can equal a full turn plus opsec_min_interval — a real safety/usability gap for an agent making destructive-capable calls.
- **What to add:** Check cancel.is_set() before each tool call inside the per-call loop and before the plan call; thread the Event into pacer.wait (use cancel_event.wait(delay) so set() returns early); set outcome='stopped' wherever it trips.
- **Files:** `ai_framework/agent/loop.py`, `ai_framework/agent/opsec.py`

#### 30. Redaction is applied to the authoritative persisted copy, so get_campaign/get_run diverge across a restart (lossy, inconsistent)
- **Severity/Effort/Module:** P2 · M · `campaign-persist`
- **Why it matters:** save() persists redact_data(model_dump()) as the ONLY on-disk copy while the in-memory object is un-redacted, so get_campaign returns un-redacted data before a restart and redacted data after — a latent contract inconsistency. It also destroys legitimately-needed material on disk (undermining any future replay) and mangles carry_over_plan/coverage that matches a credential regex before feeding it back into the next phase's prompt.
- **What to add:** Redact only at the trust boundary that crosses out (model egress, export/report), not on the primary durable record; or keep a redacted export separate from an access-controlled (0600) authoritative store. At minimum make get_campaign/get_run redact consistently pre- and post-restart, with a save/reload consistency test.
- **Files:** `ai_framework/agent/campaign.py`, `ai_framework/agent/run_store.py`, `backend/service.py`
- **Depends on:** interacts with #10 replay and #18 permissions

#### 31. Efficiency/quality of the model interface: doubled tool-schema in the system prompt, two round-trips per turn, and a self-anchoring single-step planner
- **Severity/Effort/Module:** P2 · M · `loop-core + system + models`
- **Why it matters:** build_system_prompt embeds a full json.dumps of every tool schema in the system message AND every backend also passes native tool defs — the schema is transmitted twice on every act and plan, in a spot Headroom cannot compact. Every non-terminal turn makes two LLM calls (~2x latency/cost), and plan() reuses the system with the PREVIOUS plan already folded in, biasing the new plan toward the old (drift), while spending full max_tokens on a one-line answer. The planner is single-step with no hypothesis/branch/backtrack state.
- **What to add:** Drop the raw tool-schema JSON block from the system prompt (gate it behind a backend capability flag if a non-tool-native backend ever needs it). Either merge planning into act (return next_plan alongside tool_calls) or call plan() with the BASE system (without with_plan) and cap plan max_tokens. Consider a small structured plan object (ranked hypotheses + chosen step + fallbacks) to enable branch/backtrack.
- **Files:** `ai_framework/agent/system.py`, `ai_framework/agent/loop.py`, `ai_framework/models/anthropic_backend.py`, `ai_framework/agent/contracts.py`
- **Depends on:** coordinate with #9 (plan fitting)

#### 32. No multi-target orchestration and observability is poll-the-whole-transcript with no server push
- **Severity/Effort/Module:** P2 · L · `contracts + campaign + backend`
- **Why it matters:** RunConfig.target and CampaignConfig are single-valued; a real engagement scope of N hosts means N manually-started campaigns with no shared budget, assets, memory, coverage, or cross-target finding correlation. For observability, /runs/{id} returns a full model_dump of the growing Run on every poll (O(transcript) per request) with no SSE/websocket, and the TUI's claimed 'streaming' actually prints only after the run finishes — the per-turn on_turn hook is never surfaced to a human-visible stream.
- **What to add:** Add a target-roster/engagement layer above campaigns that expands a scope into per-target runs scheduled with a shared concurrency+rate budget and merges assets/memory/coverage/findings engagement-wide (even a serial queue with shared stores + cross-target dedup closes the biggest gap). Expose an incremental channel: SSE/websocket emitting each Turn as on_turn fires, or /runs/{id}/turns?since=N; rewrite the TUI to print inside an on_turn callback.
- **Files:** `ai_framework/agent/contracts.py`, `ai_framework/agent/campaign.py`, `backend/service.py`, `backend/app.py`, `backend/tui.py`
- **Depends on:** #13 (shared budgets) for the multi-target half

#### 33. Frontend/dev-server exposure: Vite fs.allow ['..'] serves the account store, and Markdown renders to dangerouslySetInnerHTML with no sanitizer or CSP
- **Severity/Effort/Module:** P2 · M · `frontend`
- **Why it matters:** ARCHITECTURE labels both P0 but they are dev-only / currently-bounded. server.fs.allow ['..'] lets the Vite dev server serve any file under the repo root (ai_accounts.json, memory/findings stores, run transcripts) via /@fs on the same host that holds live credentials. renderDoc uses marked.parse (no raw-HTML stripping) injected via dangerouslySetInnerHTML with no DOMPurify and no CSP header; exploitability is bounded today because only the local KB/how-to content is rendered, but any future path rendering ingested/agent/target-derived Markdown becomes stored XSS.
- **What to add:** Restrict Vite fs.allow to the specific catalog/docs roots and explicitly deny store files, keep the dev server on loopback, add a test asserting /@fs disclosure of ai_accounts.json is blocked. Sanitize renderDoc output with a reviewed DOMPurify policy before dangerouslySetInnerHTML, add a restrictive Content-Security-Policy header, and add a hostile-Markdown test.
- **Files:** `frontend/vite.config.js`, `frontend/src/lib/markdown.js`, `frontend/src/components/DocView.jsx`, `frontend/src/components/HelpModal.jsx`, `backend/app.py`

#### 34. Policy hygiene: scope_digest over-invalidates approvals, legacy no-RoE allow-list ignores exclusions, and enforce_tool_policy silently no-ops without an RoE
- **Severity/Effort/Module:** P2 · M · `harness`
- **Why it matters:** scope_digest hashes the ENTIRE RoE including operator_contact/emergency_contact/evidence_directory/retention, so editing a benign contact field silently invalidates every outstanding approval token. When ctx.rules_of_engagement is absent, enforce_tool_policy returns None and ToolRegistry.execute adds no scope gate of its own, relying on each tool's require_authorized whose fallback allow-list ignores excluded_targets and always permits any subdomain — so the control plane doesn't exist for RoE-less callers.
- **What to add:** Compute the digest over only scope/policy-relevant fields (targets, exclusions, allow_subdomains, actions/flags, window, limits, autonomy, criticality), or maintain separate scope vs full-config digests and bind approvals to the scope one. Fold the legacy allow-list into a minimal RoE so target_is_in_scope (exclusions + allow_subdomains) governs both paths, and have ToolRegistry.execute fail closed when a network tool has neither an RoE nor an explicit authorized set.
- **Files:** `ai_framework/harness/policy.py`, `ai_framework/harness/runtime.py`, `ai_framework/tools/base.py`
- **Depends on:** #12 (approval-token model)

#### 35. Documentation-vs-reality drift in the READMEs and harness doc
- **Severity/Effort/Module:** P2 · M · `docs`
- **Why it matters:** The agent README credits the loop with skill-loading, research-triggering, and run checkpoint/replay it does not do; three READMEs describe a non-existent 'submit step logs' API; the top README frames SecForge as advisory-only ('never calls a provider') while a full opt-in autonomous executor ships in-repo; the '~278 markdown notes' figure is ~9x the real 31; the bilingual claim is false for the Supervisor briefing (English-only); and the harness doc states the metadata/link-local hard-deny as an enforced property that encoded IP literals bypass. Misleading docs cause operators to trust safety properties that aren't enforced.
- **What to add:** Correct the three loop-README bullets (skills are a pulled catalog, no research wiring, on_turn hook is persisted by the caller with no replay yet); remove 'submit step logs' from all three READMEs; soften 'never' to 'by default (SECFORGE_ENABLE_AUTONOMOUS)'; fix the ~278→~31 count to match ARCHITECTURE.md; scope the bilingual claim to UI/KB until the Supervisor is localized; and either implement encoded-IP normalization or soften the harness doc's deny-before-allow claim to match code. Also thread locale through the Supervisor (add locale to SessionContext, pass into build_logical_questions and render_context_block).
- **Files:** `ai_framework/agent/README.md`, `backend/README.md`, `ai_framework/README.md`, `README.md`, `docs/RED_TEAM_AGENT_HARNESS.md`, `ai_framework/supervisor/service.py`, `ai_framework/supervisor/contracts.py`
- **Depends on:** the harness-doc half tracks #1; the locale half is independent

## Missing capabilities (absent entirely)

- **Adaptive research / knowledge gap-filling** — A loop step that detects when an observed target technology, CVE, framework, or error signature falls outside the KB/skill catalog (or when the model self-reports low confidence) and automatically retrieves reference material (load_skill by matched slug, offline vuln_search KB lookup) before the next act, folding it in through the taint boundary.
  - _Rationale:_ This is the single defining feature of an ADAPTIVE agent vs one that only recombines what is already in context; the loop README claims it but no code exists, so the agent never widens its own knowledge in response to evidence.
- **Model-call resilience layer (retry/backoff/timeout + defined error terminal state)** — Bounded exponential backoff with jitter around backend.act/plan distinguishing retryable (429/5xx/timeout) from fatal (auth/schema) errors, explicit provider-client timeouts, and always setting Run.outcome='error' on exhaustion so the loop terminates in a checkpointed state regardless of caller.
  - _Rationale:_ The loop is resilient to bad tools but a single transient provider blip aborts an entire unattended campaign — the opposite of what autonomy requires, and the documented error outcome is never emitted.
- **Crash recovery / run resume** — A boot-time reconcile that scans the campaign store for orphaned 'running' campaigns, marks them 'interrupted', and either resumes run_loop from the last checkpointed turn or fails them cleanly; plus immediate persistence of held approvals so they survive a mid-phase crash.
  - _Rationale:_ Checkpoints are written every turn but nothing re-drives them; a crash bricks a campaign in 'running' with lost approvals, so the module's advertised 'recoverable/replayable' durability does not exist in any resumable sense.
- **Unified single-source action classification** — Each Tool and each run_recon Preset declaring one canonical ActionClass, from which both the campaign hold/guardrail leash and the RoE policy decision are derived, replacing the two hand-maintained classifiers that already disagree.
  - _Rationale:_ Two divergent classifiers mean every new tool can be mis-gated in one path (sqlmap already runs unapproved on non-production assets), and there is no structural guarantee the safety hold and the policy gate agree.
- **Centralized resolve-pin-and-gate egress proxy** — One choke point through which ALL target egress flows (tool session, verifier replay, browser subresources, provider clients) that performs DNS resolution, private/metadata-range rejection, IP pinning, method gating, pacing, limiting, and audit.
  - _Rationale:_ Today the harness is bypassed by the verifier and browser in-page JS, and scope is purely lexical; a single egress proxy closes the SSRF, arbitrary-verb-replay, browser-method, and unaudited-egress P0s at once instead of patching each path.
- **Single-use, expiring, finding-linked approvals and evidence custody** — Approval tokens carrying a nonce/approval-id and expiry that are consumed on use, plus an evidence_ref on every Finding pointing to the hash-chained ledger row(s) (including raw request/response) that prove it.
  - _Rationale:_ 'Require approval' currently degrades to 'approve once, replay forever', and the highest-confidence findings are the least auditable — both undermine the platform's core trust and proof-standard claims.
- **Multi-target engagement orchestration** — A roster/engagement layer above campaigns that expands a scope into per-target runs, schedules them under a shared concurrency+rate budget, and merges assets/memory/coverage/findings into an engagement-wide view with cross-target correlation.
  - _Rationale:_ A real engagement is many hosts, but runs and campaigns are single-target with per-campaign budgets, so orchestrating N hosts means N manual campaigns with no shared learning or budget accounting.
- **Live incremental observability** — An SSE/websocket or since-N delta endpoint that emits each Turn as the on_turn hook fires, and a TUI that prints inside that callback.
  - _Rationale:_ For long unattended campaigns there is no way to watch progress live — clients re-fetch the whole growing transcript per poll and the TUI only prints after the run ends, so the operator is blind during execution.
- **Local-only / provider-allowlist egress mode plus a prompt-injection taint boundary** — A config flag that refuses remote provider egress, combined with explicit untrusted-data delimiting of all target-derived text (tool logs, memory, plan) with a standing 'data not instructions' rule and a scrub pass before act/plan.
  - _Rationale:_ Untrusted target output currently reaches the provider unredacted and undelimited, and the model's own plan (derived from that output) is re-injected as a standing instruction — excessive-agency exposure with no way to contain it to a local model.
- **Engagement-wide cumulative budgets, timeouts, output caps and a kill switch** — max_total_requests/subprocesses, per-call and per-subprocess timeouts, max_response_bytes, a cancel/kill-switch hook, and persisted limiter counters rehydrated on load.
  - _Rationale:_ The limiter caps rate/concurrency but has no total ceiling, no timeouts (a hung tool can hang the worker via a timeout-less semaphore), and resets on restart, so a crash-loop or restart bypasses the whole-engagement budget.

## Test coverage gaps

- Parametrized FindingVerifier test over {GET,HEAD,OPTIONS,POST,PUT,PATCH,DELETE} asserting safe verbs replay and unsafe verbs return (False, reason) and never reach session.open (assert the stub session's recorded request.method) — the arbitrary-verb-replay P0 currently has zero regression guard (all test_verify.py cases default to GET).
- Threaded approve_action test: two concurrent calls on one approval_id assert exactly one registry.execute via a counting stub tool (the P0 double-execution race).
- Threaded continue_campaign test asserting exactly one phase thread starts; and a get_campaign-during-hold test asserting no 'list/dict changed size during iteration'.
- record_manual_action downgrade test: seed coverage with a confirmed technique, apply a failed manual action for it, assert it stays confirmed.
- Backend-failure injection test: a backend whose act()/plan() raises a transient error, asserting run.outcome=='error', run.error populated, and the partial transcript preserved.
- Headroom+plan composition test: a long run with budget active asserting the plan() call is also fitted/within budget and emits a second CompactionReport.
- Scope-bypass tests: encoded IPs (integer 2852039166, hex 0xA9FEA9FE, [::ffff:169.254.169.254]), loopback/RFC1918/ULA literals, and a hostname resolving to a private/metadata IP are all hard-denied by the resolve-and-pin guard, on the initial request and on every redirect hop.
- Ingest CONFIRMED-marker table over hyphenated technique names (Cross-Site Scripting, Server-Side Request Forgery, CSRF, SSTI, DOM-based XSS, Host-header), each with and without a [severity] bracket, asserting the correct taxonomy node is promoted.
- Ingest taint test: a target-quoted 'CONFIRMED:'/'NEW_FINDING_TYPE:' line outside the agent-authored fence does NOT mutate the notebook; and a ruled-out technique in the transcript is NOT auto-promoted by the keyword fallback.
- Contract test iterating the tool registry asserting tool_is_mutating and action_request_for_tool agree on mutating/state-change for every registered tool, and that sqlmap classifies as exploitation.
- Crash-then-reload test asserting a 'running' campaign is reconciled to 'interrupted' on boot and its held approvals were persisted (not lost).
- Concurrent JsonlAssetStore write/read test: a truncated final line is skipped by all()/summary() rather than raising.
- Loop-level guardrail+hold test: a backend that only proposes a mutating call under hold_mutating is NOT guardrail-halted for no-progress across N held turns.
- made_progress test: a stub backend that names a new technique in next_plan but exercises nothing asserts hardened_streak still increments (mention-inflation regression).
- Store-permission test asserting run/campaign/asset/finding/memory/notebook files land at 0600.
- get_campaign/get_run pre- vs post-restart consistency test asserting the returned redacted shape matches across a reload.
- Frontend tests: /@fs disclosure of ai_accounts.json is blocked by the dev server; hostile Markdown is sanitized before dangerouslySetInnerHTML.
- Locale traversal test: /i18n/../ai_accounts and encoded traversal are refused and fall back to the default locale.

## Roadmap

### Phase 1 — Make autonomy safe to enable (close the P0 egress/enforcement holes)
_Bring the six still-open P0s to a state where SECFORGE_ENABLE_AUTONOMOUS can be turned on without permitting destructive or exfiltrating traffic, backed by regression tests._

- Build the centralized resolve-pin-and-gate egress proxy: DNS resolution, encoded-IP normalization, private/metadata rejection (RoE allow_private_ranges default False), IP pinning, redirect re-validation (gap #1).
- Route the finding verifier through the policy+limiter+audit path or a safe-method allowlist, and classify its embedded repro (gap #2), with the per-verb test.
- Reclassify browser_render as active_enumeration, add method gating to the route handler, and require a scope+method callback from injected renderers (gap #3).
- Add the prompt-injection taint boundary + egress scrub + local-only flag (gap #4).
- Make approve_action a compare-and-set under lock with an idempotency key (gap #5), with the concurrency test.
- Fix /i18n locale-allowlist path traversal (gap #6) and require an authenticated session + Content-Type/CSRF on the control plane (gap #7).

### Phase 2 — Make it durable and robust for unattended runs
_Ensure a long autopilot campaign survives a flaky model and a process restart, terminates in defined states, and never double-runs or silently over-runs._

- Add model-call retry/backoff/timeout and always emit the error outcome (gaps #8, #9).
- Implement boot-time reconcile + resume and immediate held-approval persistence (gap #10); make continue/stop races safe and 'stopped' sticky (gap #11).
- Make approvals single-use/expiring and add the finding→ledger evidence link (gaps #12, #20).
- Add engagement-wide budgets/timeouts/output caps/cancellation, fix the timeout-less semaphore, persist limiter counters, and bound step_budget/max_phases (gap #13).
- Chmod all stores 0600 and fix session proxy/Authorization hygiene (gaps #18, #19).
- Fix the ingest CONFIRMED regex, ingest taint/over-promotion, and record_manual_action downgrade (gaps #15, #16, #17); harden the asset store (gap #25).

### Phase 3 — Make it a real platform (correctness, consistency, coverage)
_Collapse duplicated/diverged logic, wire dead capabilities, and give operators live visibility, so the system behaves like a professional platform rather than a demo._

- Unify action classification behind a single canonical ActionClass per tool/preset (gap #14); harden policy hygiene (scope_digest scope-only, legacy allow-list, fail-closed registry — gap #34).
- Wire ToolContext.workspace so ffuf/gobuster work and audit tool coverage vs the skill catalog (gap #23); confine project_path (gap #24).
- Replace the loop→coverage magic string with a structured held flag and fix guardrail held/mutating accounting and made_progress (gaps #26, #27, #28).
- Add live SSE/delta observability and fix the TUI stream (part of gap #32); fix redaction-on-authoritative-copy divergence (gap #30) and coarse cancellation (gap #29).
- Correct the READMEs/harness doc and thread Supervisor locale (gap #35); fix frontend dev-server exposure and Markdown sanitization (gap #33).

### Phase 4 — Make it smarter (adaptive intelligence and scale)
_Move from a single-target, recombine-what-you-have executor to a genuinely adaptive, multi-target engagement engine._

- Add the post-observation research / KB gap-filling trigger so the agent learns what it doesn't know (gap #21).
- Make memory recall relevance-driven and scalable and distil explicit lessons (gap #22).
- Deepen the planner: drop the doubled tool schema, merge or de-anchor planning, and introduce a structured hypothesis/branch/backtrack plan object (gap #31).
- Build the multi-target engagement orchestration layer with shared budgets, assets, memory, coverage, and cross-target finding correlation (gap #32).
