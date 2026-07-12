"""Findings store + report export."""

from ai_framework.notes.contracts import Confidence, Finding, FindingStatus, Severity
from ai_framework.notes.report import render_json, render_markdown
from ai_framework.notes.store import JsonlFindingStore


def test_severity_parses_and_orders():
    assert Severity.parse("HIGH") is Severity.high
    assert Severity.parse("nonsense") is Severity.info
    assert Severity.parse(4) is Severity.critical
    assert Severity.high > Severity.low


def test_store_roundtrip_and_slices(tmp_path):
    store = JsonlFindingStore(tmp_path / "f.jsonl")
    store.write(Finding(run_id="r1", target="t1", title="a", severity=Severity.low))
    store.write(Finding(run_id="r1", target="t1", title="b", severity=Severity.critical))
    store.write(Finding(run_id="r2", target="t2", title="c"))

    assert len(store.all()) == 3
    assert {f.title for f in store.for_run("r1")} == {"a", "b"}
    assert [f.title for f in store.for_target("t2")] == ["c"]
    # ranked() puts the critical first.
    assert JsonlFindingStore.ranked(store.for_run("r1"))[0].title == "b"


def test_summary_counts_by_severity(tmp_path):
    store = JsonlFindingStore(tmp_path / "f.jsonl")
    store.write(Finding(target="t", title="x", severity=Severity.high))
    store.write(Finding(target="t", title="y", severity=Severity.high))
    summary = store.summary("t")
    assert summary["total"] == 2
    assert summary["by_severity"]["high"] == 2


def test_render_markdown_and_json():
    findings = [
        Finding(target="t", title="SQLi", severity=Severity.critical, evidence="' OR 1=1"),
        Finding(target="t", title="Info leak", severity=Severity.low),
    ]
    md = render_markdown(findings, target="t", goal="assess")
    assert "# Security Assessment Report" in md
    assert "SQLi" in md and "CRITICAL" in md
    assert "' OR 1=1" in md
    # Critical is rendered before Low.
    assert md.index("SQLi") < md.index("Info leak")

    data = render_json(findings, target="t")
    assert data["total"] == 2
    assert data["by_severity"]["critical"] == 1
    assert data["findings"][0]["title"] == "SQLi"


def test_render_markdown_handles_empty():
    md = render_markdown([], target="t")
    assert "No findings recorded" in md


def test_finding_lifecycle_and_framework_metadata_render():
    finding = Finding(
        target="t",
        title="SQLi",
        severity=Severity.high,
        status=FindingStatus.reviewed,
        confidence=Confidence.high,
        cvss_score=8.1,
        cwe=["CWE-89"],
        wstg=["WSTG-INPV-05"],
        attack=["T1190"],
        affected_assets=["https://t/search"],
    )
    md = render_markdown([finding])
    assert "[reviewed]" in md
    assert "CVSS: 8.1" in md
    assert "CWE: CWE-89" in md
    assert "WSTG: WSTG-INPV-05" in md
