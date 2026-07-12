"""Build evidence-led question chains from the skills selected by the supervisor.

This is deterministic on purpose. The questions are not model-generated guesses: every one
comes from the relevant vulnerability skill, is attached to a ranked taxonomy node, and has
an explicit condition. The external testing agent answers them from observations and prunes
branches whose condition is false.
"""

from __future__ import annotations

import re

from ai_framework.skills.loader import Skill, SkillRegistry
from ai_framework.supervisor.contracts import LogicalQuestion, PlanStep
from ai_framework.supervisor.strategy import resolve_scan_mode

_PER_SKILL_BUDGET = {"quick": 2, "standard": 3, "deep": 5}
_GLOBAL_BUDGET = {"quick": 6, "standard": 18, "deep": 40}

_STAGE_RATIONALE = {
    "surface": "Establish that the relevant attack surface exists before probing it.",
    "context": "Map trust boundaries, identities, and data flow before choosing a test.",
    "fingerprint": "Identify the implementation so the next probe is compatible and specific.",
    "control": "Establish a clean baseline and a paired negative/positive comparison.",
    "validation": "Use the least-impactful reproducible test that can confirm or reject the lead.",
    "branch": "Follow this branch only when its stated precondition is supported by evidence.",
    "impact": "Demonstrate the minimum real security impact without collecting unrelated data.",
    "remediation": (
        "Check the control that should prevent the issue and make the result actionable."
    ),
}


def _safe_id(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def build_logical_questions(
    plan: list[PlanStep],
    selected_skills: list[Skill],
    registry: SkillRegistry,
    scan_mode: str = "standard",
) -> list[LogicalQuestion]:
    """Return ordered, dependency-linked questions for the ranked investigation plan."""
    mode = resolve_scan_mode(scan_mode)
    per_skill = _PER_SKILL_BUDGET[mode]
    total_budget = _GLOBAL_BUDGET[mode]
    step_by_node = {step.taxonomy_ref: step for step in plan}
    skill_by_node = {skill.catalog_slug(): skill for skill in selected_skills}
    out: list[LogicalQuestion] = []

    for step in plan:
        skill = skill_by_node.get(step.taxonomy_ref)
        if skill is None:
            continue
        previous_id = ""
        for index, source in enumerate(registry.questions(skill.name)[:per_skill], start=1):
            qid = f"{_safe_id(step.taxonomy_ref)}:{_safe_id(source.stage)}:{index}"
            stage_reason = _STAGE_RATIONALE.get(
                source.stage,
                "Resolve this hypothesis from observed evidence before moving to a stronger test.",
            )
            plan_reason = step_by_node[step.taxonomy_ref].reasoning
            out.append(
                LogicalQuestion(
                    id=qid,
                    order=len(out) + 1,
                    technique=step.taxonomy_ref,
                    skill=skill.name,
                    stage=source.stage,
                    question=source.question,
                    condition=source.condition,
                    rationale=f"{stage_reason} Plan signal: {plan_reason}",
                    depends_on=[previous_id] if previous_id else [],
                )
            )
            previous_id = qid
            if len(out) >= total_budget:
                return out
    return out
