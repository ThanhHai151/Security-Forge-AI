"""Assembles the context block handed to the external coding agent (Claude Code).

Mirrors the progressive-disclosure philosophy already documented in
``ai_framework.skills.loader``: embed the full manifest for skills the plan actually
selected, and only a compact one-line catalog for the rest, so the agent can still pull
something unanticipated without every skill's full text being force-fed up front. The
notebook-status section below follows the same principle for state: list only the
*exceptions* to "untested" (confirmed/unconfirmed/in-progress/custom), never all 29
taxonomy techniques, so a domain with a long history still costs only a few lines of tokens.
"""

from __future__ import annotations

from ai_framework.harness.contracts import HarnessBundle
from ai_framework.notebook.contracts import NodeStatus, Notebook
from ai_framework.research.archetype import ArchetypeHeuristic
from ai_framework.skills.loader import Skill, SkillRegistry
from ai_framework.supervisor.contracts import LogicalQuestion, PlanStep, SkillRef
from ai_framework.supervisor.strategy import resolve_scan_mode
from ai_framework.taxonomy.tree import Taxonomy

# Depth posture per scan mode, rendered near the top of the briefing so the external agent
# knows how far to push before it starts. Mirrors the reference tool's quick/standard/deep
# scan-mode skills, condensed to one paragraph each.
_SCAN_MODE_POSTURE: dict[str, str] = {
    "quick": (
        "**Scan mode: quick (time-boxed triage).** Lead with the high-impact classes below; "
        "skip exhaustive enumeration and low-severity or purely theoretical issues. Prove the "
        "few things that actually matter with a minimal proof-of-concept, then move on."
    ),
    "standard": (
        "**Scan mode: standard (balanced).** Cover the full attack surface for the techniques "
        "below without exhaustive depth: map the surface, test systematically area by area, "
        "then validate every candidate with a concrete proof-of-concept."
    ),
    "deep": (
        "**Scan mode: deep (exhaustive).** Map everything, test every input vector with "
        "multiple techniques, and actively chain findings. Treat low-severity issues as pivots, "
        "not noise; keep going until the high-value paths are genuinely exhausted."
    ),
}


def _render_scan_mode(scan_mode: str) -> str:
    return _SCAN_MODE_POSTURE[resolve_scan_mode(scan_mode)]


def _render_methodology(scan_mode: str, mode: str) -> str:
    """The per-technique investigation loop handed to the external agent.

    Adapted from the reference tool's Discovery -> Validation -> Reporting (-> Fixing) agent
    chain, but expressed as instructions for one coding agent to follow rather than a swarm to
    spawn. The Fix step is only included for whitebox (source-available) engagements.
    """
    steps = [
        "1. **Discovery** — map the attack surface for the class (endpoints, parameters, "
        "inputs, sinks). Prefer established scanners/tools to enumerate; don't hand-test what "
        "a tool can sweep.",
        "2. **Validation** — reproduce it with a concrete, working proof-of-concept. A scanner "
        "hit or a suspicious code path is a lead, not a finding.",
        "3. **Report** — only once reproduced, emit a `CONFIRMED` marker (see below) with the "
        "evidence: the request/response, the payload, or the code + line that proves it.",
    ]
    if mode == "whitebox":
        steps.append(
            "4. **Fix** — after reporting, patch the code in place, then re-test to confirm the "
            "fix removes the issue; include the diff in your evidence."
        )
    intro = (
        "Work each technique in the investigation order as a focused, single-purpose task — "
        "one technique × one component at a time, don't mix jobs:"
    )
    chain = (
        "Chain findings wherever one enables another (IDOR → account takeover, SSRF → cloud "
        "metadata → credentials) — a chain is worth more than the sum of its parts."
    )
    return "\n".join(["## Methodology — run this loop per technique", intro, *steps, chain])


_REPORTING_INSTRUCTIONS = """## Reporting back (keeps this notebook accurate)
When you finish investigating, report results using these exact marker lines so they can be
mechanically recorded here (one marker per line, anywhere in your final message):

CONFIRMED: <technique name> [<severity>] — <evidence / how you confirmed it>
NEW_FINDING_TYPE: <short label> — JUSTIFICATION: <why this isn't one of the existing categories>

`[<severity>]` is optional but recommended — one of critical|high|medium|low|info, scored by
real impact on THIS target (e.g. unauth full-DB write or leaked live credentials = critical).
It sets the exported report/SARIF severity for the finding instead of a generic class default.
Example: `CONFIRMED: SQL Injection [critical] — POST /api/query runs arbitrary SQL unauthenticated`

Only use NEW_FINDING_TYPE for something that doesn't fit any existing technique — don't
invent a new category for something that's really just SQL injection, XSS, SSRF, etc. under
a different name. A CONFIRMED marker records your evidence for a human to review; it does
not mark the finding as verified on its own."""


def _label_for(node_id: str, taxonomy: Taxonomy | None) -> str:
    node = taxonomy.get(node_id) if taxonomy is not None else None
    return node.label if node is not None else node_id


def _render_notebook_status(
    notebook: Notebook | None,
    archetype: ArchetypeHeuristic | None,
    taxonomy: Taxonomy | None,
) -> str:
    if notebook is None:
        return ""
    confirmed: list[str] = []
    unconfirmed: list[str] = []
    in_progress: list[str] = []
    custom: list[str] = []
    untested_count = 0

    for node_id, node in notebook.nodes.items():
        if node.in_progress:
            in_progress.append(node.note if node.is_custom else _label_for(node_id, taxonomy))
        if node.is_custom:
            custom.append(f"{node.note} ({node.status.value}) — {node.justification}")
        elif node.status == NodeStatus.confirmed:
            label = _label_for(node_id, taxonomy)
            confirmed.append(f"{label} — {node.note}" if node.note else label)
        elif node.status == NodeStatus.unconfirmed:
            label = _label_for(node_id, taxonomy)
            unconfirmed.append(f"{label} — {node.note}" if node.note else label)
        else:
            untested_count += 1

    if not (confirmed or unconfirmed or in_progress or custom or archetype):
        return ""  # nothing but "untested" — not worth a single token

    lines = [f"## Domain notebook status ({notebook.domain})"]
    if confirmed:
        lines.append("Confirmed: " + "; ".join(confirmed))
    if unconfirmed:
        lines.append("Unconfirmed (signal seen, not yet human-verified): " + "; ".join(unconfirmed))
    if in_progress:
        lines.append("Currently being tested: " + ", ".join(in_progress))
    if custom:
        lines.append("Custom findings (outside the standard taxonomy): " + "; ".join(custom))
    if untested_count:
        lines.append(f"({untested_count} other techniques untested)")
    if archetype:
        lines.append(
            f'Archetype heuristics (shared across all "{archetype.label}" targets, not '
            f"specific to this domain): boost {', '.join(archetype.priority_nodes)} — "
            f"{archetype.rationale}"
        )
    return "\n".join(lines)


def render_context_block(
    plan: list[PlanStep],
    selected_skills: list[Skill],
    registry: SkillRegistry,
    taxonomy: Taxonomy | None = None,
    notebook: Notebook | None = None,
    archetype: ArchetypeHeuristic | None = None,
    questions: list[LogicalQuestion] | None = None,
    harness: HarnessBundle | None = None,
    locale: str = "en",
    scan_mode: str = "standard",
    mode: str = "blackbox",
) -> str:
    lines: list[str] = []
    if harness is not None:
        lines.extend([harness.context_block, "", "---", ""])
    lines.extend(["# Expert Supervisor technique briefing", ""])
    lines.append(_render_scan_mode(scan_mode))
    lines.append("")

    notebook_block = _render_notebook_status(notebook, archetype, taxonomy)
    if notebook_block:
        lines.append(notebook_block)
        lines.append("")

    if plan:
        lines.append("## Investigation order (highest signal first)")
        for step in plan:
            lines.append(f"{step.order}. {step.action} — {step.reasoning}")
        lines.append("")
        if questions:
            lines.append("## Evidence-led reasoning questions")
            lines.append(
                "Answer these from logs/source in order. Treat each answer as a hypothesis "
                "decision: if its condition is false, prune that branch; never invent an "
                "answer. Prefer a paired control and the least-impactful proof."
            )
            for item in questions:
                condition = "" if item.condition == "always" else f" (condition: {item.condition})"
                lines.append(
                    f"{item.order}. [{item.technique} · {item.stage}] {item.question}{condition}"
                )
            lines.append("")
        lines.append(_render_methodology(scan_mode, mode))
        lines.append("")
    if selected_skills:
        lines.append("## Selected skill(s) — full workflow")
        for skill in selected_skills:
            text = registry.load(skill.name, locale) or ""
            lines.append(f"### {skill.name}")
            lines.append(text)
            lines.append("")
    selected_names = {s.name for s in selected_skills}
    others = [s for s in registry.skills() if s.name not in selected_names]
    if others:
        lines.append("## Other available skills (load on demand)")
        for s in others:
            lines.append(f"- {s.name}: {s.trigger()}")
        lines.append("")

    lines.append(_REPORTING_INSTRUCTIONS)
    return "\n".join(lines)


def to_skill_refs(skills: list[Skill]) -> list[SkillRef]:
    return [SkillRef(name=s.name, trigger=s.trigger()) for s in skills]
