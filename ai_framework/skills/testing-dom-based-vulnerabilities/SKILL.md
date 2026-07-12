---
name: testing-dom-based-vulnerabilities
description: >-
  Trace browser-controlled sources into dangerous DOM sinks and validate DOM XSS, open redirects, and client-side injection with benign markers.
domain: web-application-security
subdomain: client-side
tags: [dom, dom-xss, javascript, source-sink, client-side]
languages: [en]
owasp: [A03:2021-Injection]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/dom_based/README.md
---

## When to Use
A single-page app or client script reads URL, storage, message, referrer, or API data and writes it into DOM, navigation, or code-execution sinks.

## Prerequisites
- Use browser instrumentation on an authorized origin and test identity.
- Keep markers inert until the source-to-sink path and context are known.

## Reasoning Questions
- [surface] Which controllable sources reach `innerHTML`, HTML parsers, dynamic script, navigation, `eval`, timers, or `postMessage` handlers?
- [context | if a source reaches a sink] What decoding, sanitization, framework binding, and context transition occurs along the full data flow?
- [control] Does a unique inert marker reach the sink while an encoded or trusted-origin control is handled differently?
- [validation | if an executable sink is reachable] Which same-account benign marker proves execution or redirect without sending data externally?
- [impact | if client-side execution is confirmed] Which origin privileges, CSP constraints, and authenticated actions define realistic impact?

## Workflow
1. Search bundles for sources and sinks, then confirm flows with browser breakpoints or DOM instrumentation.
2. Change one source at a time and follow every transform into the final context.
3. Validate sanitizers in the actual browser; source reflection alone is not a finding.
4. Use a benign execution marker only after the exact sink is established.

## Verification
Capture the source, transform chain, sink, and observable browser behavior with an inert negative control.

## Remediation
Use safe DOM APIs, context-aware sanitization, strict `postMessage` origin checks, and Trusted Types/CSP where supported.

## Safety
Do not collect tokens, send cross-origin beacons, or expose other users to the proof.
