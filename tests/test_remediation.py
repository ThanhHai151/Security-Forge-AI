"""Findings resolve to knowledge-base fix guidance, and reports carry it inline."""

from __future__ import annotations

from ai_framework.notes.contracts import Finding, Severity
from ai_framework.notes.remediation import Remediator
from ai_framework.notes.report import render_json, render_markdown
from knowledge_base.index import default_kb


def _rem() -> Remediator:
    return Remediator(default_kb())


def test_resolves_by_tag_alias():
    rem = _rem()
    slug, guidance = rem.for_finding(Finding(title="Login bypass", tags=["sqli"]))
    assert slug == "sql_injection"
    assert guidance  # the catalog's "Defenses" section is non-empty


def test_resolves_by_kb_ref_exact():
    rem = _rem()
    slug, _ = rem.for_finding(Finding(title="whatever", kb_ref="ssrf"))
    assert slug == "ssrf"


def test_resolves_by_title_keywords():
    rem = _rem()
    slug, _ = rem.for_finding(Finding(title="Reflected XSS in search box"))
    assert slug == "xss"


def test_idor_alias_maps_to_access_control():
    rem = _rem()
    slug, _ = rem.for_finding(Finding(title="IDOR on invoice id", tags=["idor"]))
    assert slug == "broken_access_control"


def test_unmatched_finding_yields_no_guidance():
    rem = _rem()
    slug, guidance = rem.for_finding(Finding(title="Server responded to a ping"))
    assert slug == "" and guidance == ""


def test_markdown_report_includes_remediation():
    findings = [Finding(title="SQL injection in login", severity=Severity.critical, tags=["sqli"])]
    md = render_markdown(findings, target="http://x", remediator=_rem())
    assert "**Remediation**" in md
    assert "sql_injection" in md


def test_json_report_attaches_remediation():
    findings = [Finding(title="SSRF via url param", severity=Severity.high, tags=["ssrf"])]
    payload = render_json(findings, target="http://x", remediator=_rem())
    row = payload["findings"][0]
    assert row["remediation"]["kb_class"] == "ssrf"
    assert row["remediation"]["guidance"]


def test_report_without_remediator_is_unchanged():
    findings = [Finding(title="SQL injection", tags=["sqli"])]
    md = render_markdown(findings, target="http://x")
    assert "**Remediation**" not in md
    payload = render_json(findings, target="http://x")
    assert "remediation" not in payload["findings"][0]
