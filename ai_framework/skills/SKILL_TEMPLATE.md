---
name: <kebab-case-skill-name>          # 1–64 chars, must equal the folder name
description: >-                         # one keyword-rich sentence, for discovery/scan
  <What this skill lets the agent do, phrased so tag/description search finds it.>
domain: <e.g. web-application-security>
subdomain: <e.g. injection>
tags: [<tag>, <tag>, <owasp-aNN>]
languages: [en, vi]                     # locales that exist as sibling files (en = this file)
owasp: [<A03:2021-Injection>]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../vuln_search/catalog/<slug>/README.md
deep_dive: ../../../Troubleshooting_Guide/<file>.md
---

**Languages:** English · [Tiếng Việt](SKILL.vi.md)

## When to Use
Trigger conditions — the observation(s) during a run that should activate this skill.

## Prerequisites
Tools, access, and the authorization required (target must be in `RunConfig.authorized_targets`).

## Workflow
1. Ordered, concrete steps with the actual commands/requests.
2. Decision points ("if X in the response → branch to Y").
3. Keep payload depth in the deep-dive note; here, the procedure.

## Verification
How to confirm the technique worked and that the finding is real (not a false positive).
