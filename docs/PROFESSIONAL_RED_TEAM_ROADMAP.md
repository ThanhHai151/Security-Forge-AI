# Professional Red-Team Roadmap

## Purpose

SecForge is strongest as a local security-research and operator-supervised assessment
platform. It already has a knowledge base, skills, supervisor briefs, an optional tool-using
loop, scoped HTTP/browser/external-tool adapters, evidence-backed findings, campaign coverage,
and SARIF export.

This roadmap compares those foundations with the operational shape of Strix and describes the
work needed to make SecForge dependable for authorized professional engagements. It is a product
and safety roadmap, not permission to test systems outside a signed Rules of Engagement (RoE).
The controls marked **delivered** are implemented in this repository; they do not replace a
client authorization, isolated execution environment, or human operator.

## Delivered hardening

The existing red-team harness defines an operator-owned RoE. This update connects it to the
optional autonomous tool runtime:

- Every registered tool call is classified and checked against authorization, scope, exclusion,
  testing window, action policy, and approval requirements before it runs.
- Approval is a stable token bound to the exact tool arguments and the RoE digest, so approval
  cannot be reused for a different endpoint, payload, or revised scope.
- A supplied RoE takes precedence over the older broad host allow-list; localhost is no longer a
  special bypass when an explicit engagement is in force.
- HTTP redirects pass through the same scope check on every hop, closing an off-scope redirect
  escape.
- Browser subresources use the same route-level scope gate. Direct execution of browsers and
  external scanners on the host is blocked unless an isolated runner/renderer is supplied.
- Request-rate, concurrency, request-body, and per-account login-attempt limits are enforced by
  the runtime when an RoE is active.
- Provider credentials are encrypted at rest, API responses and persisted operational stores are
  redacted, and account exports exclude credentials.
- Tool results are written to a redacted, mode-0600 SHA-256 hash-chained evidence ledger, which
  can be checked with `GET /api/evidence/verify`.
- Findings carry verification state, confidence, CVSS/CWE/OWASP/WSTG/ATT&CK metadata, affected
  assets, remediation ownership, and report output. A campaign that makes no progress reports
  that bounded result instead of claiming the target is hardened.

The autonomous engine remains opt-in (`SECFORGE_ENABLE_AUTONOMOUS`). The default Supervisor flow
continues to provide a human-directed brief for an external coding agent.

## Comparison snapshot

| Capability | SecForge now | Professional next step |
|---|---|---|
| Engagement control | Typed RoE harness, preflight blockers, action gates, runtime enforcement, exact-call approval tokens | Persist signed RoEs and approvals; expose a role-based approval queue and an immutable audit trail |
| Scope safety | Target allow-list, exclusions, CIDR/domain matching in RoE, redirect and browser-subresource checking | Add DNS-rebinding controls, port/path constraints, and independent scope verification |
| Methodology | Knowledge base, scan modes, skills, reasoning questions, supervisor strategy | Version formal test plans by application type and retain coverage/evidence for every test objective |
| DAST execution | Built-in HTTP/session/browser tools plus allow-listed external adapters | Use disposable, network-restricted workers with pinned tool versions, per-job quotas, and isolated artifacts |
| Agent operations | Bounded loop, memory, campaign coverage, external-agent harness | Add role-specialized workers, deconfliction, resumable jobs, human checkpoints, and cost/turn budgets |
| Findings | Structured findings, verification, lifecycle/confidence, Markdown/JSON/SARIF, CWEs and methodology mappings | Add CVSS v4, duplicate correlation, risk acceptance, peer review, retest workflow, and executive templates |
| Evidence | Redaction before persistence, mode-0600 hash-chained ledger, integrity endpoint | Add externally witnessed/immutable storage, request/response capture policy, chain-of-custody metadata, encrypted retention |
| CI/CD | SARIF export and source review components | Ship signed CI actions/templates, diff-aware source scope, baseline comparison, and policy gates |
| Enterprise operation | Local stores and provider routing | Add RBAC/SSO, secret-manager integration, audit export, tenant separation, backup/recovery, observability, and deployment hardening |

## Implementation sequence

### Phase 0 — Safety control plane (**delivered**)

1. Keep RoE data operator-owned and validate it before any target action.
2. Enforce the RoE at the tool boundary, not only in prompts.
3. Require explicit approval for the action classes selected by the RoE.
4. Recheck redirects against scope and preserve the existing per-tool scope gates.
5. Keep autonomous execution off by default.

Exit criteria: a tool call that is off-scope, outside the window, prohibited, or unapproved
cannot execute even if a model requests it.

### Phase 1 — Engagement operations and evidence (**partially delivered**)

1. Persist an engagement record containing client, RoE digest, authorized targets, exclusions,
   test window, emergency contact, and approval history.
2. Add approval API/UI endpoints that issue and record exact-call approval tokens with actor,
   timestamp, expiry, rationale, and revocation.
3. Add target-health circuit breakers alongside the delivered request-rate, concurrency,
   authentication-attempt, and request-body runtime limits.
4. Extend the delivered hash-chained evidence ledger with tool image/version, artifact paths,
   external witnessing, and chain-of-custody signatures.
5. Add encrypted evidence retention, deletion, and legally approved data-handling controls to the
   delivered secret/session/token redaction.

Exit criteria: an operator can reconstruct who approved every material action and prove that every
finding traces to preserved, redacted evidence.

### Phase 2 — Isolated assessment runtime (**host execution blocked; worker still required**)

1. Run external tools and browsers in disposable containers/VMs with a read-only source mount,
   a per-engagement network policy, resource quotas, and no ambient cloud credentials.
2. Pin tool images and versions; record image digest and command metadata with each artifact.
3. Add target ingestion for approved URLs, repositories, IP/CIDR ranges, and asset groups; resolve
   DNS at execution time and reject scope drift.
4. Add safe testing profiles (passive, authenticated application test, source review, API test)
   with explicit allowed capabilities rather than a single broad scanner toggle.
5. Preserve the delivered browser route interception and enforce the same policy at the worker
   egress layer after DNS resolution.

Exit criteria: a failed tool or malicious target response cannot affect the operator workstation,
other engagements, or systems outside the approved network policy.

### Phase 3 — Professional assessment workflow

1. Add an asset graph that models hosts, services, endpoints, identities, roles, trust boundaries,
   and evidence relationships across multiple targets.
2. Split work into supervised specialist roles (recon, application/API, source review, cloud,
   verification, reporting) with shared notes and duplicate prevention.
3. Make runs resumable with durable checkpoints, cancellation, budgets, health signals, and a
   clear human handoff at every approval boundary.
4. Add finding correlation and lifecycle states: draft, reproduced, peer reviewed, accepted risk,
   fixed, and retested.
5. Produce client-ready reports: executive summary, methodology, scope, limitations, attack-path
   narrative, per-finding remediation, CVSS v4, retest result, and evidence references.

Exit criteria: a multi-asset engagement can be run by a team without duplicated testing or an
unexplained automated decision.

### Phase 4 — Product and enterprise hardening

1. Add SSO/RBAC with separate roles for operator, approver, reviewer, client reader, and platform
   administrator.
2. Integrate a secret manager and short-lived credentials; never place client secrets in prompts,
   transcripts, or JSONL stores.
3. Provide CI templates that run source-focused checks in pull requests and preserve a baseline
   without launching uncontrolled production scanning.
4. Add metrics, alerting, backup/restore, signed releases, dependency/SBOM generation, and a
   vulnerability disclosure process for SecForge itself.
5. Build a legal/compliance pack: data-processing posture, retention controls, export controls,
   audit exports, and report templates appropriate to the engagement's jurisdiction.

Exit criteria: the platform can be operated by more than one trusted team with clear access
boundaries, reliable recovery, and audit-ready records.

## Engineering guardrails

- Do not make payload generation or autonomous execution the primary measure of progress. Scope,
  evidence quality, verification, and operator control determine whether a result is useful.
- A model, target response, loaded document, or tool output must never be able to expand scope,
  change RoE policy, approve an action, or disable logging.
- Treat browser automation, redirects, DNS, proxies, and external CLIs as separate egress paths;
  each needs the same authorization decision.
- Prefer a proof with the least impact. Prohibit denial of service, persistence, data
  exfiltration, and destructive cleanup from automated execution.
- Keep the test corpus offline and deterministic. Every new control-plane behavior should have a
  regression test before it is exposed in the UI or a worker.

## Recommended next implementation

Build the isolated worker plus DNS-aware egress proxy before adding more scanners. The delivered
runtime can deny unsafe calls, but only an independent execution and network boundary can contain
third-party binaries, browser engines, target-controlled redirects, and DNS rebinding. In
parallel, add a persisted, signed engagement/approval record so the existing evidence ledger can
be used in an auditable professional workflow.
