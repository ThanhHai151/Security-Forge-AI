"""Skill-driven logical questions and app-archetype routing in the Expert Supervisor."""

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


def test_jwt_plan_asks_alg_none_as_a_conditional_hypothesis(tmp_path):
    advice = _service(tmp_path).advise(
        SessionContext(domain="jwt.example.test", question="the app returns a JWT error")
    )
    assert advice.plan[0].taxonomy_ref == "jwt"
    assert advice.questions
    alg_none = next(q for q in advice.questions if 'alg:"none"' in q.question)
    assert alg_none.technique == "jwt"
    assert alg_none.condition != "always"
    assert alg_none.depends_on
    assert "Evidence-led reasoning questions" in advice.context_block


def test_sql_plan_fingerprints_database_before_dialect_branch(tmp_path):
    advice = _service(tmp_path).advise(
        SessionContext(domain="db.example.test", question="investigate SQL injection")
    )
    sql_questions = [q for q in advice.questions if q.technique == "sql_injection"]
    assert [q.stage for q in sql_questions] == ["surface", "context", "fingerprint"]
    assert "database engine" in sql_questions[-1].question.lower()
    assert "Database Compatibility" in advice.context_block


def test_social_network_archetype_prioritizes_upload_access_xss_and_race(tmp_path):
    advice = _service(tmp_path).advise(
        SessionContext(
            domain="community.example.test",
            question="assess this social network with profiles, feeds, and friend requests",
            scan_mode="deep",
        )
    )
    assert advice.archetype == "social-network"
    refs = [step.taxonomy_ref for step in advice.plan]
    assert refs[:4] == ["file_upload", "broken_access_control", "xss", "race_condition"]
    assert any(q.technique == "file_upload" and "upload" in q.question.lower()
               for q in advice.questions)
    assert any(q.technique == "race_condition" for q in advice.questions)


def test_multi_user_data_app_prioritizes_boundaries_and_injection(tmp_path):
    advice = _service(tmp_path).advise(
        SessionContext(
            domain="records.example.test",
            question="general review of a multi-user data management system",
        )
    )
    assert advice.archetype == "multi-user-data-management"
    refs = [step.taxonomy_ref for step in advice.plan]
    assert refs[:3] == ["broken_access_control", "broken_authentication", "sql_injection"]


def test_scan_mode_bounds_question_depth(tmp_path):
    service = _service(tmp_path)
    quick = service.advise(
        SessionContext(domain="quick.example.test", question="general check", scan_mode="quick")
    )
    deep = service.advise(
        SessionContext(domain="deep.example.test", question="general check", scan_mode="deep")
    )
    assert 0 < len(quick.questions) <= 6
    assert len(deep.questions) > len(quick.questions)
