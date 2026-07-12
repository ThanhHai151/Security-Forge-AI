---
name: testing-information-disclosure
description: >-
  Identify and validate sensitive data exposure through errors, metadata, source maps, backups, headers, logs, and unauthenticated responses.
domain: web-application-security
subdomain: information-exposure
tags: [information-disclosure, stack-trace, metadata, secrets, source-map]
languages: [en]
owasp: [A01:2021-Broken Access Control]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/information_disclosure/README.md
---

## When to Use
Responses expose verbose errors, environment details, internal paths, credentials, source artifacts, private records, or operational metadata.

## Prerequisites
- Minimize retention and redact secrets in reports.
- Do not use exposed credentials or follow out-of-scope links without separate authorization.

## Reasoning Questions
- [surface] Which normal, invalid, unauthorized, missing-resource, debug, static-file, and metadata paths disclose different information?
- [context] Is the value public, self-owned, tenant-private, secret, regulated, or merely implementation metadata?
- [control] Does the same value remain visible when anonymous, lower-role, cross-tenant, cached, or requested through an error path?
- [validation | if sensitive material appears] Can its authenticity and scope be established from a redacted prefix, metadata, or a non-using consistency check?
- [impact | if exposure is real] What access or attack path does the disclosed item enable without actually exercising leaked credentials?

## Workflow
1. Compare controlled valid/invalid requests and inspect headers, bodies, comments, maps, manifests, and well-known metadata.
2. Classify sensitivity and authorization expectations before labeling a finding.
3. Capture only the minimum excerpt or hash needed; redact tokens, personal data, and full paths where possible.
4. Link disclosure to a realistic boundary or follow-on hypothesis, but do not use secrets automatically.

## Verification
Require a reproducible unauthorized disclosure and evidence of sensitivity; version banners alone are informational unless they create concrete risk.

## Remediation
Use production error handling, least-data responses, artifact exclusion, secret scanning/rotation, and consistent authorization on metadata routes.

## Safety
Never publish, replay, or retain more sensitive material than the engagement requires.
