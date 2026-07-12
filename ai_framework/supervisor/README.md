# `ai_framework/supervisor/` — Expert Supervisor

The Expert Supervisor is SecForge's default advisory reasoning path. It never calls an AI
provider and never sends traffic to a target. It converts an operator's domain and assessment
question into a deterministic briefing for an external coding agent.

## Flow

1. `../harness/` validates the operator-owned RoE and builds deterministic action gates, phase
   contracts, a scope digest, and the selected Claude Code/Codex/Cursor adapter.
2. `service.py` loads the target's Hermes notebook and classifies its app archetype.
3. `strategy.py` ranks catalog taxonomy nodes from the question, source signals, prior coverage,
   scan mode, and ordered archetype priorities.
4. The `catalog` link in each `SKILL.md` resolves each node to exactly one vulnerability skill.
5. `questions.py` parses the selected skills' staged question chains and emits typed questions
   with ids, conditions, rationales, and dependencies.
6. `assemble.py` renders the harness, plan, questions, full selected skills, compact
   remaining-skill catalog, notebook state, and reporting markers into one context block.
7. Pasted external-agent output is stored verbatim and only promoted to unconfirmed until a
   human marks it confirmed.

## Reasoning contract

Questions follow surface → context/fingerprint → control → validation → impact. The external
agent must answer from logs or source, use paired controls, prune a conditional branch when its
precondition is false, and stop at the minimum non-destructive evidence needed. The `quick`,
`standard`, and `deep` modes increase both the number of techniques and questions surfaced.

## Safety boundary

Advice is inert. An incomplete RoE produces a draft whose typed policy prohibits target traffic;
a ready RoE still relies on the external agent host to enforce action gates using its sandbox,
permissions, or pre-tool hook. The scope digest detects drift but is not a signature. SecForge's
legacy executor remains disabled unless `SECFORGE_ENABLE_AUTONOMOUS=1` is set explicitly; that
gate is not used or weakened by this supervisor. The full design and current conformance gaps are
documented in [`../../docs/RED_TEAM_AGENT_HARNESS.md`](../../docs/RED_TEAM_AGENT_HARNESS.md).
