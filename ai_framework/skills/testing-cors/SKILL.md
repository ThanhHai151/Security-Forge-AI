---
name: testing-cors
description: >-
  Test cross-origin policy for unsafe origin reflection, credentialed reads, null origins, preflight gaps, and route-specific inconsistencies.
domain: web-application-security
subdomain: client-side
tags: [cors, cross-origin, credentials, origin, preflight]
languages: [en]
owasp: [A05:2021-Security Misconfiguration]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/cors/README.md
---

## When to Use
Browser-facing APIs emit `Access-Control-*` headers or are called from origins outside the API host.

## Prerequisites
- Use a tester-controlled origin and test account.
- Select a read-only endpoint containing only synthetic or self-owned data.

## Reasoning Questions
- [surface] Which API responses vary their CORS policy by route, method, origin, authentication state, or error path?
- [fingerprint] Is the allowed origin fixed, reflected, regex-matched, suffix-matched, `null`, or wildcarded, and are credentials enabled?
- [control] How do trusted, untrusted, lookalike, `null`, and absent Origin controls differ in both preflight and actual responses?
- [validation | if an untrusted origin is allowed] Can JavaScript at the tester-controlled origin actually read a self-owned authenticated response in a real browser?
- [impact | if a credentialed read works] Which minimum response field proves cross-origin confidentiality impact without collecting unrelated records?

## Workflow
1. Record `Vary: Origin`, allow-origin, allow-credentials, allowed methods, and allowed headers.
2. Send paired preflight and actual requests for trusted and controlled-untrusted origins.
3. Test parser boundaries one at a time: subdomain, suffix, scheme, port, case, and `null`.
4. Confirm browser readability; raw headers that browsers reject are not exploitable CORS.

## Verification
Require a browser PoC that reads a protected self-owned value from an origin outside policy, plus a rejected negative control.

## Remediation
Use exact origin allow-lists, avoid credentialed wildcard/reflection, validate scheme/host/port, and apply policy consistently with `Vary: Origin`.

## Safety
Do not host the PoC publicly or read data belonging to other users.
