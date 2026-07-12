---
name: testing-oauth
description: >-
  Test OAuth and OIDC flows for redirect, state, nonce, PKCE, token audience, account-linking, and authorization-code binding failures.
domain: web-application-security
subdomain: authentication
tags: [oauth, oidc, pkce, redirect-uri, state, token]
languages: [en]
owasp: [A07:2021-Identification and Authentication Failures]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/oauth/README.md
---

## When to Use
The app signs users in, links accounts, or grants API access through OAuth 2.0 or OpenID Connect.

## Prerequisites
- Use tester-owned client registrations and identities where possible.
- Never capture another user's authorization code or token.

## Reasoning Questions
- [surface] Which authorization, callback, token, refresh, logout, device, and account-linking flows exist for each client?
- [fingerprint] What exact issuer, client, redirect allow-list, response mode/type, PKCE method, state, nonce, scopes, and token audience are expected?
- [control] Are code, state, nonce, verifier, redirect URI, client id, and user session each bound and single-use across paired flows?
- [branch | if multiple clients or issuers exist] Can a token/code issued for one client, tenant, redirect, or issuer be confused with another?
- [validation | if a binding appears weak] Can two tester-owned sessions prove login/account-linking confusion without exposing a third party?
- [impact | if confusion is confirmed] Which self-owned account or read-only scope demonstrates the boundary with the minimum token privileges?

## Workflow
1. Capture a clean end-to-end flow and label every browser/server/token boundary.
2. Mutate one binding at a time and compare explicit rejection controls.
3. Test redirect matching, PKCE downgrade, state/nonce reuse, code replay, and token audience only with owned clients/accounts.
4. Inspect server-side account-linking rules independently of provider authentication success.

## Verification
Require a reproducible identity, client, redirect, or audience boundary failure between tester-owned controls; an open redirect without token exposure is separate evidence.

## Remediation
Use exact redirect allow-lists, state+nonce+S256 PKCE, single-use bound codes, strict issuer/audience validation, and explicit account-link confirmation.

## Safety
Redact tokens and do not replay or intercept credentials belonging to other users.
