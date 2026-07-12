---
name: testing-graphql
description: >-
  Assess GraphQL schemas, resolvers, authorization, batching, depth, aliases, and error handling using bounded read-only queries.
domain: web-application-security
subdomain: api-security
tags: [graphql, api, introspection, resolver, batching, bola]
languages: [en]
owasp: [OWASP API Security Top 10]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/graphql/README.md
---

## When to Use
The app exposes GraphQL over HTTP/WebSocket or ships a schema/client bundle with operations.

## Prerequisites
- Use bounded queries and authorized test objects.
- Do not stress depth/complexity limits on production.

## Reasoning Questions
- [surface] Which endpoints, transports, operations, persisted-query ids, and schema artifacts expose GraphQL behavior?
- [fingerprint] Is introspection enabled, and what schema types, custom scalars, directives, resolver conventions, and error details are visible?
- [context] Where are authorization rules enforced: gateway, operation, resolver, field, object, or data layer?
- [control | if two identities exist] Does the same node/field query correctly differ across owner, non-owner, lower-role, and anonymous sessions?
- [branch | if batching aliases or nested queries are accepted] Are rate, depth, cost, pagination, and field-level controls applied after expansion?
- [impact | if a resolver boundary fails] Which single synthetic node or field proves impact with the smallest query?

## Workflow
1. Recover the schema from authorized introspection, documentation, validation errors, or client operations.
2. Build an operation × field × role matrix and test paired identities.
3. Check node/global ids, aliases, fragments, batching, subscriptions, and persisted-query controls.
4. Probe limits with tiny increments and stop well before service degradation.

## Verification
Require a concrete resolver/field authorization delta or a reproducible bounded control failure; introspection alone is normally informational.

## Remediation
Enforce authorization in every resolver/field, cap depth/cost/batches, minimize errors, and inventory persisted operations.

## Safety
No denial-of-service queries or broad enumeration; use synthetic nodes and low complexity.
