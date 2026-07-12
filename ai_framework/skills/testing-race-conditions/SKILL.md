---
name: testing-race-conditions
description: >-
  Test concurrent state transitions for TOCTOU, duplicate action, quota, counter, invite, follow, coupon, payment, and upload-processing races.
domain: web-application-security
subdomain: business-logic
tags: [race-condition, toctou, concurrency, idempotency, business-logic]
languages: [en]
owasp: [A04:2021-Insecure Design]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/race_condition/README.md
---

## When to Use
An invariant depends on check-then-use timing, counters, one-time actions, asynchronous jobs, upload quarantine, balances, inventory, invitations, or social actions.

## Prerequisites
- Model the invariant first and use tester-owned reversible state.
- Obtain approval for concurrent state changes; cap requests tightly and prepare cleanup.

## Reasoning Questions
- [surface] Which one-time tokens, balances, quotas, counters, relationship changes, moderation actions, or processing states have a check then a commit?
- [context] What invariant must remain true, which storage/queue components enforce it, and what observable state proves a violation?
- [control] What do the same two operations produce sequentially, including idempotency keys and final state?
- [validation | if an approved reversible action exists] Do two synchronized requests on one synthetic object both succeed where the sequential control permits only one?
- [branch | if processing is asynchronous] Can read/use occur before validation, quarantine, transaction commit, or revocation finishes?
- [impact | if the invariant breaks] What minimum duplicate, counter, or visibility delta proves impact, and can the synthetic state be restored immediately?

## Workflow
1. Write the invariant, initial state, allowed transition, forbidden outcome, and cleanup before sending traffic.
2. Establish sequential controls and server timestamps/ids.
3. If approved, send the smallest synchronized pair; increase concurrency only when necessary and bounded.
4. Re-read authoritative state, distinguish duplicate responses from duplicate commits, then clean up.
5. Repeat once to establish reproducibility; stop if the target shows stress or unrelated effects.

## Verification
Require a persisted invariant violation or unauthorized visibility window, not merely two HTTP 200 responses.

## Remediation
Use atomic conditional updates, transactions/locking, unique constraints, idempotency keys, and fail-closed processing states.

## Safety
Concurrency tests are state-changing: require approval, synthetic data, strict caps, and cleanup.
