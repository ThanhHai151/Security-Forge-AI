---
name: testing-clickjacking
description: >-
  Test whether sensitive UI can be framed and visually overlaid because frame-ancestor controls are missing or inconsistent.
domain: web-application-security
subdomain: client-side
tags: [clickjacking, framing, csp, x-frame-options, ui-redress]
languages: [en]
owasp: [A05:2021-Security Misconfiguration]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/clickjacking/README.md
---

## When to Use
Authenticated or privileged pages render in a browser and lack an effective CSP `frame-ancestors` policy or `X-Frame-Options` fallback.

## Prerequisites
- Use a local proof page and an authorized test account.
- Do not trick real users or activate a consequential control.

## Reasoning Questions
- [surface] Which authenticated pages contain one-click or low-interaction sensitive controls?
- [fingerprint] What effective `frame-ancestors` and `X-Frame-Options` policies reach the final response across redirects and error pages?
- [control] Can a harmless page and a sensitive page be framed from the local proof origin under the same browser conditions?
- [validation | if sensitive UI is frameable] Can a transparent overlay align with a benign control using only the tester's own session?
- [impact | if overlay is reliable] Would one click change security-sensitive state, and can that impact be documented without actually triggering it?

## Workflow
1. Inspect final response headers and CSP, including nested frames and redirect targets.
2. Build a local two-frame control page; verify browser console and framing behavior.
3. Align only a benign navigation or no-op control to demonstrate UI redress.
4. Document the sensitive action that would be exposed, but hold consequential clicks for approval.

## Verification
Capture the rendered local PoC and effective headers in a supported browser; header absence alone is insufficient when the page has no meaningful framed action.

## Remediation
Set CSP `frame-ancestors 'none'` or an explicit allow-list and retain `X-Frame-Options` for legacy clients.

## Safety
Use only tester-controlled pages and identities; never deliver the PoC to other users.
