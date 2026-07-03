"""The Expert Supervisor: deterministic skill/strategy matching, no AI-provider calls."""

from ai_framework.notebook.contracts import NodeStatus
from ai_framework.notebook.store import NotebookStore
from ai_framework.research.archetype import ArchetypeStore
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


def test_advise_matches_question_to_skill_blackbox(tmp_path):
    svc = _service(tmp_path)
    advice = svc.advise(
        SessionContext(
            domain="example.test.com",
            question="Test lỗi sql injection của hệ thống này",
        )
    )
    assert advice.plan and advice.plan[0].taxonomy_ref == "sql_injection"
    assert "exploiting-sql-injection" in {s.name for s in advice.skills}
    assert "exploiting-sql-injection" in advice.context_block


def test_advise_ranks_whitebox_files_by_grep_signal(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "def login(req):\n"
        "    cursor.execute(\"SELECT * FROM users WHERE name = '\" + req.name + \"'\")\n",
        encoding="utf-8",
    )
    (project / "utils.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    svc = _service(tmp_path)
    advice = svc.advise(
        SessionContext(
            domain="example.test.com",
            question="sql injection",
            mode="whitebox",
            project_path=str(project),
        )
    )
    step = next(s for s in advice.plan if s.taxonomy_ref == "sql_injection")
    assert "app.py" in step.reasoning
    assert "utils.py" not in step.reasoning


def test_advise_never_reinvestigates_a_confirmed_node(tmp_path):
    svc = _service(tmp_path)
    svc.notebooks.set_status("example.test.com", "sql_injection", NodeStatus.confirmed)
    advice = svc.advise(SessionContext(domain="example.test.com", question="sql injection"))
    assert not any(s.taxonomy_ref == "sql_injection" for s in advice.plan)


def test_advise_boosts_archetype_priorities_for_a_new_domain(tmp_path):
    svc = _service(tmp_path)
    advice = svc.advise(
        SessionContext(
            domain="hr.test.com",
            question="hệ thống quản lý nhân sự, kiểm tra bảo mật tổng quát",
        )
    )
    assert advice.archetype == "hr-employee-management"
    assert any(s.taxonomy_ref == "broken_authentication" for s in advice.plan)


def test_archetype_boost_never_leaks_specific_findings_across_domains(tmp_path):
    svc = _service(tmp_path)
    svc.notebooks.set_status("a.test.com", "sql_injection", NodeStatus.confirmed)
    b_notebook = svc.notebooks.get_or_create("b.test.com")
    assert b_notebook.nodes["sql_injection"].status == NodeStatus.untested


def test_advise_marks_the_top_plan_step_in_progress(tmp_path):
    svc = _service(tmp_path)
    advice = svc.advise(SessionContext(domain="example.test.com", question="sql injection"))
    notebook = svc.notebooks.load("example.test.com")
    assert notebook.nodes[advice.plan[0].taxonomy_ref].in_progress is True


def test_context_block_lists_only_exceptions_not_all_untested_nodes(tmp_path):
    svc = _service(tmp_path)
    svc.notebooks.set_status("example.test.com", "xss", NodeStatus.confirmed, note="stored xss")
    advice = svc.advise(SessionContext(domain="example.test.com", question="sql injection"))
    block_lower = advice.context_block.lower()
    assert "confirmed: cross-site scripting" in block_lower or "xss" in block_lower
    assert "other techniques untested" in advice.context_block
    # never a bare per-node "untested" listing for all 29 taxonomy techniques
    assert advice.context_block.count("untested") <= 2


def test_context_block_separates_archetype_from_domain_specific_history(tmp_path):
    svc = _service(tmp_path)
    advice = svc.advise(
        SessionContext(domain="hr.test.com", question="hệ thống quản lý nhân sự, kiểm tra bảo mật")
    )
    assert "shared across all" in advice.context_block
    assert "hr.test.com" in advice.context_block
