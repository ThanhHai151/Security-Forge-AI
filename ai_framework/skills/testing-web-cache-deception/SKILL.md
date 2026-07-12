---
name: testing-web-cache-deception
description: >-
  Test whether caches store personalized dynamic responses under attacker-shaped static-looking paths and later serve them across users.
domain: web-application-security
subdomain: server-side
tags: [cache-deception, cache, cdn, path-confusion, privacy]
languages: [en]
owasp: [A05:2021-Security Misconfiguration]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/web_cache_deception/README.md
---

## When to Use
Authenticated dynamic pages sit behind a CDN/reverse-proxy cache and path parsing or static-extension rules may disagree between cache and origin.

## Prerequisites
- Use two tester-owned identities and a unique non-sensitive canary value.
- Avoid shared production cache pollution; purge or wait for expiry after an approved proof.

## Reasoning Questions
- [surface] Which personalized routes are cache-adjacent, and which extensions, delimiters, path segments, query keys, or rewrite rules trigger caching?
- [fingerprint] How do CDN and origin normalize path parameters, suffixes, encoding, case, and trailing segments?
- [control] What are cache status, age, key, and body results for anonymous and two authenticated controls on the canonical path?
- [validation | if a static-looking variant caches] Can user A seed only a synthetic canary that user B or anonymous later receives at the same variant?
- [impact | if cross-user cache reuse occurs] Which personalized field classes would be exposed under that key without collecting real user content?

## Workflow
1. Establish cache headers and canonical personalized behavior with tester-owned accounts.
2. Vary one path rule at a time using unique canaries and low request counts.
3. Seed as account A, then fetch as account B/anonymous only after authorization to test shared state.
4. Purge or document expiry and verify the canonical route was not altered.

## Verification
Require a cache hit serving A's unique benign canary to B/anonymous with paired miss controls; path oddities alone are not findings.

## Remediation
Never cache authenticated/private responses by default, align path normalization, key on required identity dimensions, and set explicit private/no-store policy.

## Safety
Use synthetic content, unique keys, cleanup, and approval before touching a shared cache.
