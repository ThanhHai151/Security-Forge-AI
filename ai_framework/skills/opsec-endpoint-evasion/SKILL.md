---
name: opsec-endpoint-evasion
description: >-
  Reason about EDR/endpoint telemetry and cross-OS stealth (Windows ETW/AMSI, macOS TCC/ESF,
  Linux eBPF, containers) and delivery (MOTW/ASR) at the concept level — always paired with detection.
domain: offensive-security
subdomain: endpoint-opsec
tags: [opsec, edr, etw, amsi, macos, tcc, linux, ebpf, containers, motw, delivery, detection]
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
The engagement involves an **endpoint** (Windows, macOS, Linux, or a container) and you need to
reason about what its EDR/telemetry can see, or about how a payload is delivered and what blocks it.
This skill is concept + detection only — no bypass recipes. Depth and sources:
[`docs/RED_TEAM_OPSEC.md` §8](../../../docs/RED_TEAM_OPSEC.md).

## Prerequisites
- Authorized target; any state-changing action is proposed for operator approval, not auto-run.
- Know the ATT&CK v19 split: tampering with controls is **Defense Impairment (TA0112)**; pure
  concealment is **Stealth (TA0005)** (§1).

## Workflow (what to reason about, per surface)
1. **Windows EDR (§8.1).** Telemetry comes from user-mode hooks, kernel callbacks, and ETW.
   Concept-level evasions (unhooking, direct/indirect syscalls, ETW/AMSI tamper, BYOVD) are all
   Defense Impairment — assume they are *noisy to a kernel-sourced sensor*, not free.
2. **macOS (§8.2).** Guardrails: TCC (consent), Gatekeeper + notarization, `com.apple.quarantine`;
   EDR consumes the Endpoint Security Framework (ESF). Since **macOS 15.4**, ESF emits
   `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY`, so TCC grant/revoke is now natively observable.
3. **Linux (§8.2).** Offense and defense both live at eBPF; classic tradecraft (`LD_PRELOAD`,
   `memfd_create` fileless) is countered by auditd and eBPF sensors (Falco/Tetragon).
4. **Containers/K8s (§8.2).** Footprint shifts to service-account token theft, RBAC abuse, and
   breakout; runtime detection is Falco + eBPF + Kubernetes audit logs.
5. **Delivery (§8.3).** HTML smuggling (T1027.006) and ISO/LNK favor stripping **Mark-of-the-Web**;
   the defense is MOTW propagation + SmartScreen + ASR rules.

## Verification (name the detection for each surface)
- **Windows:** kernel-ETW call-stack analysis, Vulnerable-Driver Blocklist/HVCI, absence-of-telemetry.
- **macOS:** ESF `TCC_MODIFY` events (15.4+) with instigator/service/right/reason context; pre-15.4
  defenders had only fragile private TCC-daemon log messages.
- **Linux/containers:** eBPF/Falco/Tetragon runtime rules, auditd, K8s audit logging.
- **Delivery:** Protected View / macro block on MOTW files, SmartScreen, ASR child-process rules.

> **Note:** §8's endpoint/C2 material is broader than it is deeply multi-source-verified (see the
> doc's coverage note). Treat these as pointers to the primary sources cited in §8/§12, not settled
> fact — verify current specifics before relying on them.
