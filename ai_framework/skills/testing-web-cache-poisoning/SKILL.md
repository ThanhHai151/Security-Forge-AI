---
name: testing-web-cache-poisoning
description: >-
  Test whether unkeyed request inputs influence cacheable responses and can persist benign attacker-controlled content across clients.
domain: web-application-security
subdomain: server-side
tags: [cache-poisoning, cache-key, cdn, headers, normalization]
languages: [en]
owasp: [A03:2021-Injection]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/web_cache_poisoning/README.md
---

## When to Use
A cacheable response varies on headers, query parameters, cookies, method overrides, or routing inputs that may be absent from the cache key.

## Prerequisites
- Prefer staging or a unique unlinked cache key with a harmless canary.
- Obtain approval and define purge/expiry cleanup before any shared-cache confirmation.

## Reasoning Questions
- [surface] Which request components affect redirects, links, scripts, metadata, variants, error bodies, or routing in cacheable responses?
- [fingerprint] Which components are normalized and included in the actual cache key, and what do `Vary`, age, and cache-status reveal?
- [control] Does a canary input alter the origin response, and does a different input on the same suspected key normally miss or hit?
- [validation | if influence is unkeyed] Can a benign canary persist only at a unique test URL and appear in a clean follow-up request that omits it?
- [impact | if persistence is confirmed] Which security-relevant response context is controllable without injecting active content into shared pages?

## Workflow
1. Find cacheable low-impact responses and create a unique isolated key.
2. Compare origin influence and cache-key behavior one input at a time.
3. If approved, seed an inert marker, fetch it cleanly, and immediately purge or allow documented expiry.
4. Keep active script/redirect consequences theoretical unless a dedicated environment exists.

## Verification
Require an omitted-input follow-up cache hit containing the unique marker plus a non-poisoned control key.

## Remediation
Key every response-influencing input or reject it, normalize consistently, avoid caching unsafe errors/redirects, and add cache-policy tests.

## Safety
Never poison popular paths or serve active content to uninvolved users.
