---
name: testing-http-request-smuggling
description: >-
  Investigate front-end/back-end HTTP parsing differentials with isolated, low-rate probes and non-poisoning confirmation techniques.
domain: web-application-security
subdomain: server-side
tags: [http, request-smuggling, desync, proxy, cl-te, h2]
languages: [en]
owasp: [A03:2021-Injection]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/http_request_smuggling/README.md
---

## When to Use
Multiple HTTP hops parse requests, and transfer framing, HTTP/2 downgrade, connection reuse, or timing behavior suggests a desynchronization.

## Prerequisites
- Prefer a local replica or dedicated staging route; production testing needs explicit approval.
- Use single connections, unique canaries, low rate, and no victim-request capture.

## Reasoning Questions
- [surface] What client, CDN, load balancer, reverse proxy, gateway, and origin protocol chain parses the request?
- [fingerprint] How does each hop normalize duplicate length, transfer-encoding variants, whitespace, line endings, and HTTP/2 pseudo-headers?
- [control] What are stable timing and response baselines for well-formed requests on a fresh isolated connection?
- [validation | if parsers disagree] Can a timeout or self-contained canary response demonstrate desync without poisoning another user's connection?
- [impact | if desync is repeatable] Which routing, cache, or response-queue boundary is affected in the isolated environment?

## Workflow
1. Reproduce the hop chain locally where possible and identify protocol conversions.
2. Send one framing variation per fresh connection, bracketed by well-formed controls.
3. Stop on instability; never run bulk differential scans against shared production pools.
4. Confirm with a self-owned canary request in staging, then document production applicability from configuration evidence.

## Verification
Require a repeatable parser differential or self-contained desync signal across controls; a lone timeout is not a finding.

## Remediation
Normalize or reject ambiguous framing at the edge, align parser versions/configuration, avoid unsafe downgrades, and close suspect connections.

## Safety
This class can disrupt shared traffic. Keep active confirmation isolated and explicitly approved.
