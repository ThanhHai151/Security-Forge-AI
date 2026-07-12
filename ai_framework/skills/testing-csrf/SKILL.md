---
name: testing-csrf
description: >-
  Test browser state-changing flows for missing anti-CSRF tokens, unsafe cookie semantics, and weak Origin or Referer enforcement.
domain: web-application-security
subdomain: client-side
tags: [csrf, session, samesite, origin, browser]
languages: [en]
owasp: [A01:2021-Broken Access Control]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/csrf/README.md
---

## When to Use
Cookie-authenticated browser endpoints change state through forms, JSON, multipart, or method-override flows.

## Prerequisites
- Use a tester-owned account and choose a reversible, low-impact preference when possible.
- Obtain approval before any state-changing proof that cannot be safely reversed.

## Reasoning Questions
- [surface] Which security-sensitive actions rely on ambient cookies, including alternate methods and content types?
- [fingerprint] Which defenses apply: synchronizer token, double-submit cookie, SameSite, custom header, Origin/Referer, or re-authentication?
- [control] What happens when the token is absent, stale, from another session, duplicated, moved, or paired with a foreign Origin?
- [validation | if a reversible action is approved] Can a cross-site form from a tester-controlled origin change only the tester's benign preference?
- [impact | if cross-site state change works] Which higher-impact action shares the same missing control and can be documented without executing it?

## Workflow
1. Inventory state-changing routes and their cookie/token/origin requirements.
2. Replay paired same-site requests while changing one defense input at a time.
3. Account for browser SameSite rules, top-level navigation, redirects, and legacy endpoints.
4. If approved, use a local cross-site PoC against a reversible self-owned setting and restore it.

## Verification
Require a real browser cross-site request and observable approved state delta; a tokenless request sent by a raw HTTP client is not sufficient by itself.

## Remediation
Use framework CSRF protection, strict Origin checks, suitable SameSite cookies, and re-authentication for consequential actions.

## Safety
Keep proofs local, reversible, and limited to the tester's account.
