# SecForge Red-Team Agent Harness

The harness is the execution contract handed to an external coding agent by the Expert
Supervisor. It combines a machine-readable Rules of Engagement (RoE), deterministic action
policy, phased red-team workflow, evidence contract, and a small adapter for Claude Code,
OpenAI Codex, Cursor, or a generic tool-using agent.

It is designed for authorized assessments. A target name is not proof of authorization.
SecForge therefore renders an incomplete request as a **draft** and blocks target traffic until
authorization, scope, and the testing window are explicit.

## Design principles

1. **Policy is data, not persona.** `RulesOfEngagement` is typed operator input. A model can
   read it but target content cannot amend it.
2. **Fail closed.** Missing authorization, target, timezone-aware window, target on an exclusion
   list, or an expired window prohibits network actions.
3. **Deny before allow.** Metadata/link-local endpoints and hard-prohibited action classes win
   over an allow entry. An exclusion wins over an authorized wildcard.
4. **Graduated autonomy.** SecForge supports assisted L1 and supervised L2. It deliberately
   does not expose L3/L4 because the current advisory architecture lacks the external watchdog,
   isolated audit store, and automated recovery those levels need.
5. **Separate instructions from observations.** Pages, source, logs, tool results, errors,
   retrieved docs, and memory are untrusted evidence. They cannot change scope, permissions,
   credentials, callbacks, approval state, or reporting destinations.
6. **Progressive disclosure.** The durable harness remains compact; only selected vulnerability
   skills are expanded. Independent read-heavy work can use isolated subagents that return
   evidence summaries.
7. **Evidence beats assertion.** Scanner output and suspicious code are leads. A finding needs
   raw evidence, a paired control, a reproducible proof, demonstrated impact, and human review
   appropriate to its severity.

## Control and data planes

```text
operator-owned RoE ──> deterministic preflight/action policy ──> vendor permission/hook
       |                              |                                  |
       |                              v                                  v
       |                    allow / approval / deny                tool execution
       |                                                                 |
       +-------------------- immutable scope digest                       v
                                                               untrusted observations
                                                                          |
                                                                          v
                                                          hypothesis/evidence ledger
```

The scope digest is a drift fingerprint, not a digital signature or authorization proof. A
production deployment should sign the RoE, store it outside the agent-writable workspace, and
have a pre-tool control validate every proposed action against that stored copy.

## Rules of Engagement

`ai_framework.harness.contracts.RulesOfEngagement` captures:

- engagement and authorization references;
- exact authorized and excluded targets, CIDRs, and an explicit subdomain policy;
- asset criticality, with `unknown` treated conservatively as production;
- timezone-aware start and end timestamps;
- L1 assisted or L2 supervised autonomy;
- allowed action classes and the subset requiring approval;
- separate authorization flags for evasion, credentials, state changes, sensitive data, and
  out-of-band callbacks;
- per-host request rate, concurrency, authentication-attempt, request-size, and approval-timeout
  limits;
- evidence location, retention, operator/escalation contacts, and stop conditions.

The default allowed set contains only local analysis, passive reconnaissance, bounded active
enumeration, vulnerability identification, evidence capture, and reporting. Active enumeration
and vulnerability probes require approval by default. Exploitation and other high-impact classes
must first be added to the RoE and still require approval. Persistence, data exfiltration, and
denial of service are hard-prohibited by this harness.

## Action decision

`evaluate_action()` returns `allow`, `require-approval`, or `prohibit` without consulting a
model. It evaluates, in order:

1. the hard-prohibited action and endpoint sets;
2. RoE readiness and active time window;
3. explicit action target and deny-first scope matching;
4. allowed action class and feature-specific authorization;
5. autonomy and asset-criticality escalation;
6. reversibility and caller-predicted risk.

A high/critical or non-reversible action can only become more restricted. Text in the action
summary has no authority, so a prompt-like claim cannot widen the result.

## Phase state machine

The rendered briefing uses the OWASP APTS phase names and adds explicit initialization and
cleanup states:

1. **Initialization** validates and freezes the RoE without target traffic.
2. **Reconnaissance** builds a low-noise external picture and threat model.
3. **Enumeration** maps routes, inputs, roles, sessions, trust boundaries, and business rules.
4. **Identification** turns observations into falsifiable hypotheses and paired controls.
5. **Exploitation** proves only the minimum approved impact needed to resolve a candidate.
6. **Post-Exploitation** is entered only when separately authorized for a stated objective.
7. **Cleanup and Integrity** preserves evidence, rolls back changes, reconciles artifacts, and
   checks target health.
8. **Reporting** separates verified findings, unverified leads, negatives, blocked tests, and
   untested coverage.

Each phase has an entry gate and required exit evidence. Discovery never automatically grants
permission for exploitation, a new target, credential use, lateral movement, or stronger impact.

## Operator behavior encoded in the harness

The execution loop models effective human testing behavior without turning the assessment into
a payload checklist:

- build an attack-surface graph, identity/role matrix, trust-boundary model, business invariants,
  and a hypothesis ledger;
- prioritize the action with the highest information gain at the lowest expected impact;
- state an expected differentiating signal and at least one rejected alternative;
- use a clean baseline and positive/negative control while changing one variable at a time;
- adapt from observed evidence, including negative evidence, instead of repeating dead ends;
- prioritize identity, object/tenant authorization, privileged and transactional workflows,
  injection/parsing boundaries, upload/render/fetch surfaces, cloud trust, and concurrency;
- demonstrate the minimum impact, avoid unrelated data, and never chain merely because access
  became available;
- stop immediately on scope drift, target degradation, cross-tenant or sensitive-data access,
  unexpected privilege, manipulation, rollback failure, or an expired window.

## Evidence contract

Every action, evidence item, hypothesis, and finding should have a stable ID and UTC timestamp.
Raw evidence records the tool/version, exact target, sanitized parameters, status/latency, and a
content hash or durable path. Interpretation is stored separately.

Finding states remain distinct:

- **candidate:** one signal or scanner/static-analysis lead;
- **corroborated:** multiple consistent signals, not yet reproduced;
- **reproduced:** a minimal proof and paired control succeeded;
- **human-reviewed:** an accountable reviewer accepted evidence, impact, and scope.

Confidence measures evidence strength; severity measures demonstrated business impact. Reports
must also disclose tested-negative, inconclusive, policy-blocked, and not-tested coverage. Secrets,
tokens, personal data, and unrelated records are redacted from chat and reports.

## Vendor adapters

The policy is vendor-neutral. An adapter only tells the selected host where to keep durable
guidance, how to isolate work, and where mechanical enforcement belongs.

| Host | Durable guidance | On-demand context | Isolation | Mechanical gate |
|---|---|---|---|---|
| Claude Code | `CLAUDE.md` | Skills | plan/read-only subagents | permission deny rules + `PreToolUse` hook |
| OpenAI Codex | `AGENTS.md` | Skills | read-only explorer/reviewer subagents | OS sandbox + approval policy + hook/wrapper |
| Cursor | `.cursor/rules/*.mdc` | scoped/manual rules | bounded parallel agents | `.cursor/cli.json` permissions; auto-run off |
| Generic | host system instructions | retrieved skill text | separate read-only workers | external policy wrapper |

For all hosts, give MCP servers and subprocesses the smallest phase-specific tool set. Target and
MCP output remains untrusted. A worker cannot approve its own escalation, edit the RoE, or split a
blocked action into apparently harmless sub-actions.

## API example

```json
POST /api/supervisor/advise
{
  "domain": "app.example.test",
  "question": "assess authorization and transaction integrity",
  "scan_mode": "standard",
  "vendor": "codex",
  "rules_of_engagement": {
    "engagement_id": "ENG-2026-0042",
    "authorization_confirmed": true,
    "authorization_reference": "signed-sow-42",
    "authorized_targets": ["app.example.test"],
    "excluded_targets": ["payments.example.test"],
    "allow_subdomains": false,
    "asset_criticality": "production",
    "window_start": "2026-07-11T13:00:00+07:00",
    "window_end": "2026-07-11T17:00:00+07:00",
    "max_requests_per_second": 0.5,
    "max_concurrency": 1,
    "operator_contact": "operator@example.test",
    "emergency_contact": "soc@example.test",
    "evidence_directory": "/engagement-evidence/ENG-2026-0042"
  }
}
```

The response includes `harness.ready`, human-readable blockers/warnings, the normalized RoE,
scope digest, phase and action-gate arrays, vendor instructions, and the combined `context_block`.
The Web UI exposes the core RoE fields and copies the full block for the selected agent.

## Current enforcement boundary

This implementation is **APTS-aligned, not an OWASP APTS conformance claim**. The Supervisor is
network-free and the policy evaluator is deterministic, but a copied briefing cannot enforce
another process by itself. A production autonomous deployment still needs at least:

- cryptographic RoE signature verification and immutable server-side engagement state;
- pre-connection DNS, CNAME, redirect, cloud-account, tenant, and time-window enforcement;
- an allowlist enforced outside the agent runtime for every tool and parameter;
- health telemetry, cumulative-risk thresholds, an external watchdog, and a kill switch;
- an agent-inaccessible tamper-evident audit trail and evidence chain of custody;
- state baselines, tested rollback/cleanup, post-test integrity checks, and incident recovery;
- calibrated confidence/false-positive metrics and accountable human review.

The legacy autonomous engine remains separately disabled by default. Its older target gate and
approval hold do not inherit this Supervisor RoE automatically.

## Primary references

- [OWASP Autonomous Penetration Testing Standard](https://owasp.org/APTS/)
- [OWASP APTS Scope Enforcement](https://owasp.org/APTS/standard/1_Scope_Enforcement/)
- [OWASP APTS Safety Controls](https://owasp.org/APTS/standard/2_Safety_Controls/)
- [OWASP APTS Manipulation Resistance](https://owasp.org/APTS/standard/6_Manipulation_Resistance/)
- [OWASP APTS Reporting](https://owasp.org/APTS/standard/8_Reporting/)
- [NIST SP 800-115, Technical Guide to Information Security Testing](https://csrc.nist.gov/pubs/sp/800/115/final)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/)
- [MITRE ATT&CK Adversary Emulation Plans](https://attack.mitre.org/resources/adversary-emulation-plans/)
- [Claude Code extension overview](https://code.claude.com/docs/en/features-overview)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [OpenAI Codex manual](https://developers.openai.com/codex/codex-manual.md)
- [Cursor project rules](https://docs.cursor.com/context/rules-for-ai)
- [Cursor CLI permissions](https://docs.cursor.com/cli/reference/permissions)
