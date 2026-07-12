---
name: attacking-jwt
description: >-
  Test JSON Web Token verification for signature-stripping (alg:none), weak HMAC secrets, and claim tampering, then forge a token to prove impact — with the `jwt_attack` tool.
domain: web-application-security
subdomain: authentication
tags: [jwt, authentication, crypto, web, owasp-a02, alg-none, hs256]
languages: [en]
owasp: [A02:2021-Cryptographic Failures]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/jwt/README.md
---

## When to Use
The app issues a JWT (Authorization: Bearer / cookie); the token's header shows `alg:HS256`/`none`; claims include `role`/`user`/`admin`.

## Prerequisites
- The target host is in `RunConfig.authorized_targets` (the tool safety gate enforces this).
- A session established via `login`/`set_auth` if the surface is authenticated.
- The candidate input/endpoint identified during recon (track it with `record_asset`).

## Reasoning Questions
- [surface] Where is the JWT issued, refreshed, revoked, and accepted, and which endpoint gives a harmless authorization oracle?
- [fingerprint | if a JWT is present] What are its `alg`, `kid`, key-source headers, issuer, audience, subject, roles, and expiry semantics?
- [branch | if the header algorithm can be changed] Does verification explicitly reject an unsigned `alg:"none"` token rather than trusting the token header?
- [branch | if HMAC or key-reference headers are used] Are weak HMAC secrets, asymmetric-to-HMAC confusion, or untrusted `kid`/`jku`/`x5u` key selection plausible for this implementation?
- [validation | if a signing or claim-validation weakness is supported] Does one locally forged, non-destructive token change access at the harmless oracle while an invalid-signature control is rejected?
- [impact | if forged access is confirmed] Which single claim or scoped read demonstrates the authorization boundary without modifying data?

## Workflow
1. Decode the token (`jwt_attack op=decode`) and record header, registered claims, and the endpoint that verifies it.
2. Establish controls: replay the original token, a one-byte-corrupted signature, and an expired/audience-mismatched token where safe.
3. If the implementation signals justify it, forge `alg-none` locally and replay it only against a read-only authorization oracle.
4. For HS256, test only a small authorized weak-secret set; if a secret is proven, use `forge-hs256` with the minimum changed claim.
5. Test asymmetric/HMAC confusion only when the public key and accepted algorithm family are known; never assume the token header controls server policy.
6. Test `kid`/`jku`/`x5u` only when the header is accepted and scope permits the referenced key source.
7. Record the original, negative control, forged token, and response delta; a decodable token alone is not a finding.

## Representative payloads
- `alg:none unsigned token`
- `HS256 forged with a cracked secret`
- `kid path traversal / SQL in kid`

## Evidence to capture
The forged token + an authenticated response it unlocks (e.g. admin data). `jwt_attack` forges locally; replay against the authorized target to prove it.

## Remediation
Pin the expected algorithm server-side, reject `none`, use strong secrets/asymmetric keys, and validate all registered claims.

## Safety
Authorized targets only. Prefer the least-noisy proof; never run destructive payloads on your
own — if a state-changing test is warranted, propose it and let the operator approve it.
