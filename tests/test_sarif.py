"""Tests for the notebook -> SARIF 2.1.0 exporter (ai_framework.report.sarif).

Mirrors the reference tool's ``findings.sarif`` intent: confirmed/unconfirmed technique nodes
become code-scanning results with CWE-backed rules, STRIDE tags, and stable fingerprints. Pure
and deterministic — no AI call, no target access.
"""

from ai_framework.notebook.contracts import NodeStatus, Notebook, NotebookNode
from ai_framework.report.sarif import SARIF_VERSION, notebook_to_sarif
from ai_framework.taxonomy.tree import Taxonomy


def _nb(nodes: dict[str, NotebookNode]) -> Notebook:
    return Notebook(id="x", domain="app.example.test", nodes=nodes)


def test_empty_notebook_yields_valid_empty_sarif():
    doc = notebook_to_sarif(_nb({}))
    assert doc["version"] == SARIF_VERSION
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SecForge"
    assert doc["runs"][0]["results"] == []
    assert driver["rules"] == []


def test_only_confirmed_and_unconfirmed_become_results():
    nodes = {
        "sql_injection": NotebookNode(
            id="sql_injection", status=NodeStatus.confirmed, note="union-based on /login"
        ),
        "xss": NotebookNode(id="xss", status=NodeStatus.unconfirmed),
        "ssrf": NotebookNode(id="ssrf", status=NodeStatus.untested),
    }
    doc = notebook_to_sarif(_nb(nodes), taxonomy=Taxonomy())
    results = doc["runs"][0]["results"]
    by_id = {r["ruleId"]: r for r in results}
    assert set(by_id) == {"sql_injection", "xss"}  # untested excluded
    assert by_id["sql_injection"]["level"] == "error"
    assert by_id["xss"]["level"] == "warning"
    assert "union-based on /login" in by_id["sql_injection"]["message"]["text"]
    # DAST-style: anchored to the domain as a logical location (no source file).
    loc = by_id["sql_injection"]["locations"][0]["logicalLocations"][0]
    assert loc["name"] == "app.example.test"


def test_rule_carries_cwe_helpuri_severity_and_stride():
    nodes = {"sql_injection": NotebookNode(id="sql_injection", status=NodeStatus.confirmed)}
    doc = notebook_to_sarif(_nb(nodes))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "sql_injection"
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/89.html"
    props = rule["properties"]
    assert float(props["security-severity"]) >= 8.0
    assert "external/cwe/CWE-89" in props["tags"]
    assert any(t.startswith("stride/") for t in props["tags"])
    assert "security" in props["tags"]


def test_custom_node_uses_its_note_as_label_and_does_not_crash():
    nodes = {
        "custom:weird-thing": NotebookNode(
            id="custom:weird-thing",
            status=NodeStatus.confirmed,
            note="Weird business logic bypass",
            is_custom=True,
            justification="doesn't map to a standard class",
        )
    }
    doc = notebook_to_sarif(_nb(nodes))
    result = doc["runs"][0]["results"][0]
    assert "Weird business logic bypass" in result["message"]["text"]
    assert result["properties"]["is_custom"] is True
    # unmapped slug -> default severity, still a valid rule (no CWE helpUri required)
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "security-severity" in rule["properties"]


def test_fingerprint_is_stable_and_scoped_to_domain_and_node():
    node = {"sql_injection": NotebookNode(id="sql_injection", status=NodeStatus.confirmed)}
    fp1 = notebook_to_sarif(_nb(node))["runs"][0]["results"][0]["partialFingerprints"]
    fp2 = notebook_to_sarif(_nb(node))["runs"][0]["results"][0]["partialFingerprints"]
    assert fp1["secforgePrimary"] == fp2["secforgePrimary"]
    assert len(fp1["secforgePrimary"]) == 16


def test_service_notebook_sarif_reflects_confirmed_status(tmp_path):
    from backend.service import RunService

    service = RunService(
        memory_path=None,
        findings_path=None,
        runs_dir=None,
        campaigns_dir=None,
        assets_path=None,
        notebook_dir=str(tmp_path / "nb"),
        archetype_path=str(tmp_path / "arch.json"),
        raw_log_path=None,
    )
    service.supervisor.notebooks.set_status(
        "api.example.test", "ssrf", NodeStatus.confirmed, note="hit cloud metadata"
    )
    doc = service.notebook_sarif("api.example.test")
    results = doc["runs"][0]["results"]
    assert any(r["ruleId"] == "ssrf" and r["level"] == "error" for r in results)
    assert doc["runs"][0]["properties"]["domain"] == "api.example.test"
