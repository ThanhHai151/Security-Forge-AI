"""Defense (Pillar 4).

The defensive counterpart to the pentest framework: point it at a web codebase you own and
it finds weak spots and maps each to concrete hardening. It shares the offense side's
knowledge — every finding links to its catalog class and that class's "Defenses" guidance
(``ARCHITECTURE.md`` › "Offense and defense share one core"). Read-only: generated fixes are
proposals. See ``defense/README.md``.
"""

from __future__ import annotations

from defense.deps import (
    Advisory,
    Dependency,
    DependencyFinding,
    DependencyReport,
    parse_dependencies,
    scan_dependencies,
)
from defense.review import DefenseReport, Finding, recheck, review_path
from defense.signatures import Signature, default_signatures

__all__ = [
    "Advisory",
    "DefenseReport",
    "Dependency",
    "DependencyFinding",
    "DependencyReport",
    "Finding",
    "Signature",
    "default_signatures",
    "parse_dependencies",
    "recheck",
    "review_path",
    "scan_dependencies",
]
