---
name: testing-llm-attacks
description: >-
  Assess LLM applications for direct and indirect prompt injection, unsafe tool use, cross-user data leakage, insecure output handling, and weak trust boundaries.
domain: web-application-security
subdomain: llm-security
tags: [llm, prompt-injection, rag, tools, agents, data-leakage]
languages: [en]
owasp: [OWASP Top 10 for LLM Applications]
version: "0.1"
author: secforge
license: Apache-2.0
catalog: ../../../vuln_search/catalog/llm_attacks/README.md
---

## When to Use
The app sends user or retrieved content to a model, exposes tools/actions, stores conversational memory, or renders model output into another trust domain.

## Prerequisites
- Use synthetic canaries and tester-owned documents/accounts.
- Do not request real secrets, execute consequential tools, or target third-party model infrastructure.

## Reasoning Questions
- [surface] Which system instructions, user prompts, retrieved documents, memories, tool results, images, and external pages enter the model context?
- [context] Which data and actions belong to different users, tenants, privilege levels, or trust zones?
- [fingerprint] What model, retrieval, tool-approval, output-rendering, and memory controls constrain untrusted instructions?
- [control] Does a synthetic conflicting instruction stay data when supplied directly, indirectly through retrieval, and through a tool result?
- [validation | if instruction/data boundaries fail] Can a unique canary be disclosed or a harmless no-op tool be proposed without accessing real secrets or changing state?
- [impact | if control is bypassed] Which cross-user data, tool privilege, or downstream rendering boundary would be reachable under the demonstrated path?

## Workflow
1. Draw the context/data/tool trust-boundary map before crafting any test.
2. Seed unique non-sensitive canaries in tester-owned sources and vary one instruction channel at a time.
3. Keep tools in dry-run/no-op mode and verify server-side authorization independently of model intent.
4. Test output encoding separately when model content reaches HTML, SQL, shell, or templates.
5. Record the complete input provenance, model response, policy decision, and blocked control.

## Verification
A model repeating hostile text is not enough; require a boundary violation such as canary disclosure, unauthorized tool proposal/execution, or unsafe downstream interpretation.

## Remediation
Separate instructions from data, authorize tools server-side, minimize context, isolate tenants/memory, require approval, and encode downstream output.

## Safety
No real credential extraction, harmful content, or state-changing tool invocation.
