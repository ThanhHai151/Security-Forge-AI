---
name: testing-http-host-header
description: >-
  Test whether untrusted Host and forwarded-host headers influence absolute URLs, routing, cache keys, security links, or tenant selection.
domain: web-application-security
subdomain: server-side
tags: [host-header, x-forwarded-host, routing, reset-poisoning, cache]
languages: [en]
owasp: [A03:2021-Injection]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/http_host_header/README.md
---

## When to Use
The app constructs absolute links, routes tenants, caches responses, or trusts proxy forwarding headers.

## Prerequisites
- Use an in-scope alternate hostname or inert canary value.
- Trigger email/reset flows only for a tester-owned account and with approval.

## Reasoning Questions
- [surface] Which redirects, canonical links, password-reset URLs, asset URLs, cache entries, and tenant routes incorporate host information?
- [fingerprint] Which of `Host`, absolute-form targets, `X-Forwarded-Host`, `Forwarded`, and duplicate headers wins across each proxy hop?
- [control] How do the canonical host, an in-scope alternate, and an invalid canary affect body, headers, routing, and cache behavior?
- [validation | if host input reaches a security link] Can a preview/log or tester-owned reset message prove poisoning without sending content to another user?
- [impact | if routing or cache varies unsafely] Does the influence cross tenant, origin, or trust boundaries under a reproducible negative control?

## Workflow
1. Establish the canonical host and proxy chain from normal responses.
2. Vary one host source at a time at low rate and record final routing/URL generation.
3. Check cache keys and tenant selection without polluting shared content.
4. If approved, exercise a tester-owned email flow and capture only that message.

## Verification
Require a generated or routed security-relevant artifact controlled by the canary host; a reflected Host value in a diagnostic page is not enough.

## Remediation
Allow-list canonical hosts, configure trusted proxies explicitly, and generate security URLs from server configuration rather than request headers.

## Safety
Avoid shared-cache pollution and messages to non-test identities.
