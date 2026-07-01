---
name: red-team-opsec
description: >-
  Stay covert on an authorized engagement: pick the least-noisy action, spend effort where it
  hurts defenders (up the Pyramid of Pain), pace traffic, and document without destroying.
domain: offensive-security
subdomain: opsec-tradecraft
tags: [opsec, stealth, evasion, attribution, pyramid-of-pain, detection, blue-team]
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
Every authorized engagement where staying undetected matters (i.e. by default). Load this before
acting on a live target, whenever you are about to generate network/host traffic, or when deciding
whether a noisier action is worth it.

## Prerequisites
- A signed authorization / Rules of Engagement; the target host is in `RunConfig.authorized_targets`.
- OPSEC pacing available (`opsec_min_interval` / `opsec_jitter`) for live work.
- Deep reference: [`docs/RED_TEAM_OPSEC.md`](../../../docs/RED_TEAM_OPSEC.md) (§0 authorization,
  §1 Pyramid of Pain, §2–§8 the layers, §10 the ATT&CK quick-map).

## Workflow
1. **Authorize first (§0).** Confirm the target is in scope. An out-of-scope lead is *noted and
   left untouched* — never followed.
2. **Pick the least-noisy action that still proves the point.** Favour read-only recon; a
   state-changing (`mutating`) action is proposed for operator approval, never auto-run.
3. **Know where you are on the Pyramid of Pain (§1).** Rotating IPs / spoofing a timezone is the
   *cheapest, weakest* move. Durable evasion is reshaping tool/behaviour fingerprints (JA4+, beacon
   cadence) and TTPs — don't burn effort at the bottom of the pyramid.
4. **Pace + blend (§2–§4).** Add interval + jitter so the cadence isn't a beacon; prefer
   living-off-the-land and legitimate-looking traffic over dropping obvious artifacts.
5. **Mind the up-stack surfaces (§5–§8).** Identity/cloud (OAuth/token, Kerberos, cloud-log
   integrity) and endpoint telemetry (EDR/ETW/AMSI) are watched as closely as the network; load the
   matching skill (`opsec-cloud-identity`, …) when that surface is in play.
6. **Document, don't destroy (§0, §6).** Keep a precise, timestamped log of every action; never
   delete the client's logs, corrupt data, or perform destructive anti-forensics.

## Verification
- Every action is reproducible from the logged request/step (audit trail intact).
- No out-of-scope asset was touched; no client evidence was destroyed.
- For each noticeable action, you can name its **detection counterpart** (how a defender would see
  it) — if you can't, consult the relevant section of the deep-dive before proceeding.
