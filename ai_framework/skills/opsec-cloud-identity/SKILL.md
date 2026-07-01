---
name: opsec-cloud-identity
description: >-
  Stay covert in identity and cloud control planes — OAuth/token replay, Entra PRT abuse,
  Kerberos ticket forgery, and cloud-log tampering — each paired with how defenders detect it.
domain: offensive-security
subdomain: cloud-identity-opsec
tags: [opsec, cloud, identity, entra, oauth, kerberos, active-directory, token-theft, detection]
languages: [en, vi]
owasp: []
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../docs/RED_TEAM_OPSEC.md
deep_dive: ../../../docs/RED_TEAM_OPSEC.md
---

**Languages:** English · [Tiếng Việt](SKILL.vi.md)

## When to Use
The engagement touches an **identity or cloud control plane** — Microsoft Entra ID / Azure, AWS,
GCP, or on-prem Active Directory — and stealth matters. Signals: OAuth/consent flows, access/refresh
tokens, Kerberos tickets, or cloud audit configuration are in scope. Full context and citations:
[`docs/RED_TEAM_OPSEC.md` §7](../../../docs/RED_TEAM_OPSEC.md).

## Prerequisites
- The target tenant/account/domain is authorized in `RunConfig.authorized_targets`.
- Understand that here the detection surface is **logs and sign-ins**, not host EDR.
- State-changing steps (registering a device, disabling logging, forging a ticket) are **proposed
  for operator approval**, never auto-run.

## Workflow
1. **Cloud logging is a Defense-Impairment target (ATT&CK T1562.008).** If an assessment includes
   log-integrity testing, know the three moves — stop (`StopLogging` / sink `disabled=true`), make
   unreadable (KMS-key repoint + revoke), redirect (attacker bucket) — and that each is itself a
   config-change event. Prefer *documenting the gap* over exercising it.
2. **Identity: prefer token/consent over malware (T1528 · T1550.001 · T1566).** OAuth consent
   phishing abuses legitimate first-party client IDs (e.g. VS Code) for a `.default` token; the
   advanced path exchanges an Authentication-Broker refresh token for a **Primary Refresh Token**
   (SSO). Remember a PRT *inherits* an MFA already performed — it does not defeat MFA, and a
   compliant-device Conditional-Access policy can still block a rogue device.
3. **AD: forge the ticket, skip the guard (T1558).** A **Silver Ticket** (forged TGS) never touches
   a Domain Controller, so DC events (4769) don't fire — plan detection on the host/service side.
4. **Blend into normal API/sign-in patterns**: reuse expected client IDs, regions, and working
   hours; a token used from an impossible location or an `unbound` session is the tell.

## Verification (the detection counterpart — confirm you can name it)
- **Token/OAuth:** Entra ID Protection *Anomalous token* (offline), Defender-for-Endpoint PRT-access
  alert, and multi-log correlation (`app_id`, `resource_id`, `sign_in_session_status="unbound"`).
- **Cloud logs:** config-change events, org-level trails, immutable sinks, sink-modification rules.
- **Kerberos:** hunt RC4 tickets (etype 0x17 — rare since AES is default; Server 2025 stops RC4),
  PAC validation, host-side 4624/4634 anomalies. (Do **not** use the disproven "TGS without a prior
  TGT = Golden Ticket" heuristic.)
