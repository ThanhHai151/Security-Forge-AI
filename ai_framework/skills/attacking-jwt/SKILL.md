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

## Workflow
1. Decode the token (`jwt_attack op=decode`) and read header + claims.
2. Try `alg-none` forge with an escalated claim; replay it via `set_auth`+`http_request`.
3. Try `crack-hs256` against the weak-secret list; if cracked, `forge-hs256` a new token.
4. Test `kid`/`jku`/`x5u` header injection where present.

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
