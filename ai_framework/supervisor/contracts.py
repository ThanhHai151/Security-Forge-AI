"""Data contracts for the Expert Supervisor — advisory output only, no execution."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SessionContext(BaseModel):
    """What the operator told the supervisor before asking Claude Code to act."""

    domain: str
    question: str
    mode: str = "blackbox"  # "whitebox" | "blackbox" — explicit choice, never auto-detected
    project_path: str | None = None  # required for "whitebox" ranking to do anything


class SkillRef(BaseModel):
    name: str
    trigger: str = ""


class PlanStep(BaseModel):
    order: int
    action: str
    reasoning: str
    taxonomy_ref: str = ""


class Advice(BaseModel):
    """The supervisor's whole response to one ``advise()`` call."""

    domain: str
    archetype: str = ""
    plan: list[PlanStep] = Field(default_factory=list)
    skills: list[SkillRef] = Field(default_factory=list)
    context_block: str = ""
