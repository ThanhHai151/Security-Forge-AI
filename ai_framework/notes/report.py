"""Render captured findings into a shareable pentest report (Markdown or JSON).

Pure functions over ``Finding`` records, so the same output serves the CLI, the API
(``GET /runs/{id}/report``), and tests. Findings are presented worst-first; a severity tally
heads the report so a reader sees the shape at a glance.
"""

from __future__ import annotations

from ai_framework.notes.contracts import Finding, Severity
from ai_framework.notes.store import JsonlFindingStore

_ORDER = sorted(Severity, key=int, reverse=True)  # critical -> info


def _tally(findings: list[Finding]) -> dict[str, int]:
    counts = {s.name: 0 for s in _ORDER}
    for f in findings:
        counts[f.severity.name] += 1
    return counts


def render_json(findings: list[Finding], *, target: str = "") -> dict:
    ranked = JsonlFindingStore.ranked(findings)
    return {
        "target": target,
        "total": len(ranked),
        "by_severity": _tally(ranked),
        "findings": [f.model_dump(mode="json") for f in ranked],
    }


def render_markdown(findings: list[Finding], *, target: str = "", goal: str = "") -> str:
    ranked = JsonlFindingStore.ranked(findings)
    tally = _tally(ranked)
    lines: list[str] = ["# Security Assessment Report", ""]
    if target:
        lines.append(f"**Target:** {target}  ")
    if goal:
        lines.append(f"**Objective:** {goal}  ")
    lines.append(f"**Findings:** {len(ranked)}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in _ORDER:
        lines.append(f"| {sev.name.capitalize()} | {tally[sev.name]} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not ranked:
        lines.append("_No findings recorded._")
        return "\n".join(lines)
    for i, f in enumerate(ranked, 1):
        badge = " ✅ verified" if f.verified else " ⚠️ unverified"
        lines.append(f"### {i}. {f.title} — {f.severity.name.upper()}{badge}")
        lines.append("")
        if f.detail:
            lines.append(f.detail)
            lines.append("")
        if f.verification:
            lines.append(f"**Verification:** {f.verification}")
            lines.append("")
        if f.evidence:
            lines.append("**Evidence:**")
            lines.append("")
            lines.append("```")
            lines.append(f.evidence)
            lines.append("```")
            lines.append("")
        meta = []
        if f.target:
            meta.append(f"target `{f.target}`")
        if f.kb_ref:
            meta.append(f"see KB: {f.kb_ref}")
        if f.tags:
            meta.append("tags: " + ", ".join(f.tags))
        if meta:
            lines.append("_" + " · ".join(meta) + "_")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"
