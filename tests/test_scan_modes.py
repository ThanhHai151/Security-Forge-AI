"""Tests for supervisor scan modes (quick/standard/deep) — depth posture + methodology.

Mirrors the reference tool's quick/standard/deep scan modes, but the supervisor stays
deterministic: the mode only changes how many techniques the plan surfaces, whether the
order is biased toward high-impact classes, and the posture/methodology rendered into the
briefing. No AI-provider call is involved.
"""

from ai_framework.notebook.store import NotebookStore
from ai_framework.research.archetype import ArchetypeStore
from ai_framework.supervisor import strategy
from ai_framework.supervisor.contracts import SessionContext
from ai_framework.supervisor.service import SupervisorService
from ai_framework.taxonomy.tree import Taxonomy


def _service(tmp_path) -> SupervisorService:
    taxonomy = Taxonomy()
    return SupervisorService(
        taxonomy=taxonomy,
        notebooks=NotebookStore(tmp_path / "notebooks", taxonomy=taxonomy),
        archetypes=ArchetypeStore(tmp_path / "archetypes.json"),
    )


def test_resolve_scan_mode_normalizes_unknown_to_standard():
    assert strategy.resolve_scan_mode("quick") == "quick"
    assert strategy.resolve_scan_mode("DEEP") == "deep"
    assert strategy.resolve_scan_mode(" Standard ") == "standard"
    assert strategy.resolve_scan_mode("") == "standard"
    assert strategy.resolve_scan_mode(None) == "standard"
    assert strategy.resolve_scan_mode("banana") == "standard"


def test_quick_mode_caps_the_plan_at_three_steps(tmp_path):
    svc = _service(tmp_path)
    advice = svc.advise(
        SessionContext(
            domain="t.example.test", question="assess this application", scan_mode="quick"
        )
    )
    assert 0 < len(advice.plan) <= strategy.SCAN_MODE_STEP_BUDGET["quick"] == 3


def test_deep_mode_surfaces_more_steps_than_quick(tmp_path):
    svc = _service(tmp_path)
    q = "please take a broad look at this"
    quick = svc.advise(SessionContext(domain="a.example.test", question=q, scan_mode="quick"))
    deep = svc.advise(SessionContext(domain="b.example.test", question=q, scan_mode="deep"))
    assert len(deep.plan) > len(quick.plan)
    assert len(deep.plan) <= strategy.SCAN_MODE_STEP_BUDGET["deep"] == 8


def test_default_scan_mode_is_standard_budget(tmp_path):
    svc = _service(tmp_path)
    advice = svc.advise(
        SessionContext(domain="c.example.test", question="review the whole application")
    )
    assert len(advice.plan) <= strategy.SCAN_MODE_STEP_BUDGET["standard"] == 6


def test_quick_mode_leads_with_a_high_impact_class(tmp_path):
    svc = _service(tmp_path)
    # A neutral question that names no specific technique and no archetype, so the only thing
    # steering the order is quick mode's high-impact bias.
    advice = svc.advise(
        SessionContext(domain="neutral.example.test", question="general check", scan_mode="quick")
    )
    assert advice.archetype == ""
    assert advice.plan[0].taxonomy_ref in strategy.HIGH_IMPACT_NODES


def test_context_block_states_the_scan_mode_posture(tmp_path):
    svc = _service(tmp_path)
    for mode, marker in [("quick", "quick (time-boxed"), ("deep", "deep (exhaustive")]:
        advice = svc.advise(
            SessionContext(domain=f"{mode}.example.test", question="sql injection", scan_mode=mode)
        )
        assert marker in advice.context_block
        assert "Scan mode:" in advice.context_block


def test_methodology_block_includes_fix_step_only_in_whitebox(tmp_path):
    svc = _service(tmp_path)
    black = svc.advise(SessionContext(domain="bb.example.test", question="sql injection"))
    assert "## Methodology" in black.context_block
    assert "**Discovery**" in black.context_block
    assert "**Fix**" not in black.context_block

    white = svc.advise(
        SessionContext(domain="wb.example.test", question="sql injection", mode="whitebox")
    )
    assert "**Fix**" in white.context_block


def test_whitebox_surfaces_a_source_detected_technique_not_named_in_the_question(tmp_path):
    # Regression for the QLNS /api/query blind-spot: a raw-SQL passthrough endpoint in the
    # source must show up in the plan even though the operator only asked about auth.
    project = tmp_path / "project"
    project.mkdir()
    (project / "query.ts").write_text(
        "export async function runQuery(req) {\n"
        "  const sqlText = req.body.sql;\n"
        "  return await client.execute(sqlText);\n"
        "}\n",
        encoding="utf-8",
    )
    svc = _service(tmp_path)
    advice = svc.advise(
        SessionContext(
            domain="wb-src.example.test",
            question="check the authentication logic",  # names auth, NOT sql
            mode="whitebox",
            project_path=str(project),
        )
    )
    refs = {s.taxonomy_ref for s in advice.plan}
    assert "sql_injection" in refs  # discovered from source, not from the question


def test_endpoint_phrasing_routes_to_api_and_sql_techniques(tmp_path):
    # "the /api/query endpoint" should reach both api_security and sql_injection now.
    svc = _service(tmp_path)
    advice = svc.advise(
        SessionContext(domain="ep.example.test", question="please test the /api/query endpoint")
    )
    refs = {s.taxonomy_ref for s in advice.plan}
    assert "sql_injection" in refs
    assert "api_security" in refs


def test_backend_advise_forwards_scan_mode(tmp_path):
    # The RunService.advise wrapper (what the HTTP handler calls) must forward scan_mode into
    # the SessionContext so the posture reaches the briefing. Stores nulled/temp'd to keep the
    # repo clean.
    from backend.service import RunService

    service = RunService(
        memory_path=None,
        findings_path=None,
        runs_dir=None,
        campaigns_dir=None,
        assets_path=None,
        notebook_dir=str(tmp_path / "notebook_store"),
        archetype_path=str(tmp_path / "archetype_store.json"),
        raw_log_path=None,
    )
    result = service.advise(domain="svc.example.test", question="sql injection", scan_mode="quick")
    assert "quick (time-boxed" in result["context_block"]
    assert result["questions"] and result["questions"][0]["technique"] == "sql_injection"
    default = service.advise(domain="svc2.example.test", question="sql injection")
    assert "standard (balanced" in default["context_block"]


def test_scan_mode_does_not_change_which_technique_ranks_first_for_a_named_question(tmp_path):
    # A question that clearly names SQLi should still lead with sql_injection in every mode —
    # the mode changes depth, not the top hit.
    svc = _service(tmp_path)
    for scan_mode in ("quick", "standard", "deep"):
        advice = svc.advise(
            SessionContext(
                domain=f"named-{scan_mode}.example.test",
                question="test for sql injection with sqlmap",
                scan_mode=scan_mode,
            )
        )
        assert advice.plan[0].taxonomy_ref == "sql_injection"
