---
name: testing-websockets
description: >-
  Assess WebSocket handshakes, origin checks, authentication lifetime, per-message authorization, schema validation, and bounded resource controls.
domain: web-application-security
subdomain: api-security
tags: [websocket, realtime, origin, authorization, message]
languages: [en]
owasp: [A05:2021-Security Misconfiguration]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/websockets/README.md
---

## When to Use
The app uses `ws://`/`wss://`, Socket.IO, GraphQL subscriptions, or another long-lived bidirectional browser channel.

## Prerequisites
- Use tester-owned channels, rooms, messages, and identities.
- Keep connection/message counts low; this skill is not a load test.

## Reasoning Questions
- [surface] Which handshake URLs, subprotocols, fallback transports, events, rooms, topics, and message schemas exist?
- [fingerprint] Where are Origin, cookie/token, CSRF, subprotocol, and session-expiry checks enforced—handshake only or per message?
- [control] How do owner, non-owner, lower-role, expired-token, foreign-Origin, and anonymous controls differ for the same subscription/action?
- [branch | if identifiers select rooms or objects] Does changing only the id bypass per-message object authorization or leak events?
- [validation | if a boundary is missing] Can one synthetic event or self-owned room prove unauthorized read/send access without contacting real users?
- [impact | if access persists] Does logout, revocation, role change, or token expiry terminate existing authorization promptly?

## Workflow
1. Capture the browser handshake and message sequence, including reconnect/fallback behavior.
2. Build an event × role × object matrix and replay one field change at a time.
3. Test Origin and authentication lifetime with paired controls at low rate.
4. Validate schema/size limits using small malformed messages; do not flood connections.

## Verification
Require an unauthorized synthetic message, room subscription, or post-revocation action with a rejected control; handshake success alone is not a finding.

## Remediation
Validate Origin and schema, authorize every message/object, bind subscriptions to identity, revoke live sessions, and cap connections/message size/rate.

## Safety
No message floods, oversized frames, or interaction with non-test users/rooms.
