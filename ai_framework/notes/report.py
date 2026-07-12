"""Render captured findings into a shareable pentest report (Markdown or JSON).

Pure functions over ``Finding`` records, so the same output serves the CLI, the API
(``GET /runs/{id}/report``), and tests. Findings are presented worst-first; a severity tally
heads the report so a reader sees the shape at a glance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_framework.notes.contracts import Finding, Severity
from ai_framework.notes.store import JsonlFindingStore

if TYPE_CHECKING:
    from ai_framework.notes.remediation import Remediator

_ORDER = sorted(Severity, key=int, reverse=True)  # critical -> info


def _tally(findings: list[Finding]) -> dict[str, int]:
    counts = {s.name: 0 for s in _ORDER}
    for f in findings:
        counts[f.severity.name] += 1
    return counts


def render_json(
    findings: list[Finding], *, target: str = "", remediator: Remediator | None = None
) -> dict:
    ranked = JsonlFindingStore.ranked(findings)
    rows: list[dict] = []
    for f in ranked:
        row = f.model_dump(mode="json")
        if remediator is not None:
            slug, guidance = remediator.for_finding(f)
            if slug:
                row["remediation"] = {"kb_class": slug, "guidance": guidance}
        rows.append(row)
    return {
        "target": target,
        "total": len(ranked),
        "by_severity": _tally(ranked),
        "findings": rows,
    }


def render_markdown(
    findings: list[Finding], *, target: str = "", goal: str = "",
    remediator: Remediator | None = None,
) -> str:
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
        lines.append(
            f"### {i}. {f.title} — {f.severity.name.upper()}{badge} [{f.status.value}]"
        )
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
        if remediator is not None:
            slug, guidance = remediator.for_finding(f)
            if guidance:
                lines.append(f"**Remediation** (`{slug}`):")
                lines.append("")
                lines.append(guidance)
                lines.append("")
        meta = []
        if f.target:
            meta.append(f"target `{f.target}`")
        if f.kb_ref:
            meta.append(f"see KB: {f.kb_ref}")
        if f.tags:
            meta.append("tags: " + ", ".join(f.tags))
        meta.append(f"confidence: {f.confidence.value}")
        if f.cvss_score is not None:
            meta.append(f"CVSS: {f.cvss_score:.1f}")
        if f.cvss_vector:
            meta.append(f"vector: {f.cvss_vector}")
        if f.cwe:
            meta.append("CWE: " + ", ".join(f.cwe))
        if f.wstg:
            meta.append("WSTG: " + ", ".join(f.wstg))
        if f.attack:
            meta.append("ATT&CK: " + ", ".join(f.attack))
        if f.affected_assets:
            meta.append("assets: " + ", ".join(f.affected_assets))
        if f.remediation_owner:
            meta.append(f"owner: {f.remediation_owner}")
        if meta:
            lines.append("_" + " · ".join(meta) + "_")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"
