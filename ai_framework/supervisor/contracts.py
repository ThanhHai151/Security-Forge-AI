"""Data contracts for the Expert Supervisor — advisory output only, no execution."""

from __future__ import annotations

from pydantic import BaseModel, Field

from ai_framework.harness.contracts import HarnessBundle, RulesOfEngagement, Vendor


class SessionContext(BaseModel):
    """What the operator told the supervisor before asking Claude Code to act."""

    domain: str
    question: str
    mode: str = "blackbox"  # "whitebox" | "blackbox" — explicit choice, never auto-detected
    project_path: str | None = None  # required for "whitebox" ranking to do anything
    # Depth posture, mirroring the reference tool's quick/standard/deep scan modes. Controls
    # how many techniques the plan surfaces, whether the order is biased toward high-impact
    # classes, and the methodology posture rendered into the briefing. Unknown values fall
    # back to "standard" (see ``strategy.resolve_scan_mode``).
    scan_mode: str = "standard"  # "quick" | "standard" | "deep"
    # The model-facing briefing is built from this operator-owned policy object. Missing RoE
    # fields are allowed at advice time but produce a DRAFT harness that blocks target traffic.
    vendor: Vendor = Vendor.generic
    rules_of_engagement: RulesOfEngagement | None = None


class SkillRef(BaseModel):
    name: str
    trigger: str = ""


class PlanStep(BaseModel):
    order: int
    action: str
    reasoning: str
    taxonomy_ref: str = ""


class LogicalQuestion(BaseModel):
    """One evidence question in a skill-driven hypothesis chain."""

    id: str
    order: int
    technique: str
    skill: str
    stage: str
    question: str
    condition: str = "always"
    rationale: str = ""
    depends_on: list[str] = Field(default_factory=list)


class Advice(BaseModel):
    """The supervisor's whole response to one ``advise()`` call."""

    domain: str
    archetype: str = ""
    plan: list[PlanStep] = Field(default_factory=list)
    skills: list[SkillRef] = Field(default_factory=list)
    questions: list[LogicalQuestion] = Field(default_factory=list)
    harness: HarnessBundle
    context_block: str = ""
