---
name: attacking-authentication
description: >-
  Test login, session, and recovery flows for weak credentials, missing lockout, session fixation, and predictable tokens on an authorized target.
domain: web-application-security
subdomain: authentication
tags: [authentication, session, brute-force, web, owasp-a07, credential-stuffing]
languages: [en]
owasp: [A07:2021-Identification and Authentication Failures]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/broken_authentication/README.md
---

## When to Use
A login/reset flow with no rate limit or MFA; verbose 'user not found' vs 'bad password'; session ids that don't rotate after login.

## Prerequisites
- The target host is in `RunConfig.authorized_targets` (the tool safety gate enforces this).
- A session established via `login`/`set_auth` if the surface is authenticated.
- The candidate input/endpoint identified during recon (track it with `record_asset`).

## Reasoning Questions
- [surface] Which login, registration, recovery, MFA, and logout flows establish or change identity?
- [control | if an authentication flow exists] Do paired valid and invalid attempts differ in body, status, timing, or rate-limit behavior?
- [validation | if a session can be established] Does the session identifier rotate after login, privilege change, password reset, and logout?
- [impact | if a control is missing] What is the smallest authorized account set that proves enumeration, replay, fixation, or weak recovery without broad guessing?
- [remediation | if source or configuration is available] Where should uniform errors, throttling, MFA, token entropy, and session rotation be enforced?

## Workflow
1. Enumerate valid users via response/timing differences.
2. Test lockout/rate-limit with a small, authorized credential set (never mass attacks).
3. Check session fixation (does the id rotate on login?) and cookie flags.
4. Probe password-reset token entropy and reuse.

## Representative payloads
- `username enumeration via error/timing delta`
- `session id unchanged pre/post login`
- `reset token reuse / weak entropy`

## Evidence to capture
The differing responses (enumeration), an un-rotated session id, or a reusable reset token. Keep credential tests small and authorized; attach `repro`.

## Remediation
Uniform auth errors, rate limiting + lockout, MFA, rotate session ids on login, and high-entropy single-use reset tokens.

## Safety
Authorized targets only. Prefer the least-noisy proof; never run destructive payloads on your
own — if a state-changing test is warranted, propose it and let the operator approve it.
