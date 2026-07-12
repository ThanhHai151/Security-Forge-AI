"""Vendor-neutral red-team execution harness.

The harness is deliberately split from the model prompt. ``RulesOfEngagement`` and
``evaluate_action`` are deterministic policy data/code; renderers only explain those
decisions to an external coding agent.
"""

from ai_framework.harness.contracts import (
    ActionClass,
    ActionDisposition,
    ActionGate,
    ActionRequest,
    ActionRisk,
    AssetCriticality,
    AutonomyLevel,
    HarnessBundle,
    HarnessPhase,
    PolicyDecision,
    RulesOfEngagement,
    Vendor,
)
from ai_framework.harness.policy import build_harness, evaluate_action, preflight_blockers

__all__ = [
    "ActionClass",
    "ActionRequest",
    "ActionRisk",
    "ActionGate",
    "ActionDisposition",
    "AssetCriticality",
    "AutonomyLevel",
    "HarnessBundle",
    "HarnessPhase",
    "PolicyDecision",
    "RulesOfEngagement",
    "Vendor",
    "build_harness",
    "evaluate_action",
    "preflight_blockers",
]
