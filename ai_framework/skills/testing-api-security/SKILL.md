---
name: testing-api-security
description: >-
  Assess REST and RPC APIs for missing object/function authorization, unsafe field binding, weak inventory, excessive data exposure, and resource-control failures.
domain: web-application-security
subdomain: api-security
tags: [api, rest, bola, mass-assignment, inventory, owasp-api]
languages: [en]
owasp: [OWASP API Security Top 10]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/api_security/README.md
---

## When to Use
The target exposes REST/RPC endpoints, mobile APIs, versioned routes, or machine-readable schemas.

## Prerequisites
- Test only in-scope hosts with documented test identities and data ownership.
- Inventory requests before mutation; hold state-changing probes for operator approval.

## Reasoning Questions
- [surface] Which hosts, versions, methods, content types, schemas, mobile routes, and undocumented endpoints make up the API inventory?
- [context] Which identity, tenant, object owner, role, and field-level rules should apply to each route?
- [control | if two authorized identities exist] Does the same object/function request change correctly across owner, non-owner, anonymous, and lower-role controls?
- [branch | if bodies bind directly to models] Are server-managed fields, nested objects, or alternate content types accepted through mass assignment?
- [validation | if a boundary appears missing] Can one synthetic object or read-only field prove BOLA, BFLA, or excessive exposure without touching real user data?
- [impact | if controls are bypassed] Can endpoints be chained across versions or workflows to increase impact beyond the single request?

## Workflow
1. Build a method × route × role × object matrix from docs, traffic, and schemas.
2. Replay one request at a time with only identity, object id, method, content type, or field set changed.
3. Check old versions, alternate methods, bulk/export routes, filters, pagination, and error shapes.
4. Test limits with small bounded samples; do not load-test production through this skill.
5. Record exact paired controls and the minimum synthetic evidence for every confirmed boundary failure.

## Verification
A finding requires a reproducible response or state difference that violates the documented role/object rule; route existence or a scanner label is only a lead.

## Remediation
Centralize deny-by-default object/function checks, allow-list writable fields, minimize responses, inventory versions, and enforce bounded resource limits.

## Safety
Authorized targets only. Prefer reads and synthetic test objects; propose state changes before execution.
