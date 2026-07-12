"""Skill loader, on-demand load_skill tool, and system-prompt catalog injection."""

from ai_framework.agent.contracts import RunConfig, ToolCall
from ai_framework.agent.system import build_system_prompt
from ai_framework.skills.loader import SkillRegistry, _parse_frontmatter, _questions
from ai_framework.tools.base import ToolContext, ToolRegistry
from ai_framework.tools.skills_tool import LoadSkillTool

_SYNTHETIC = """---
name: demo-skill
description: >-
  A folded description that spans
  two source lines.
tags: [alpha, beta]
languages: [en, vi]
---

**Languages:** English

## When to Use
When the trigger condition is observed on an authorized target.

## Workflow
1. Do the thing.
"""


def _skill_dir(tmp_path, name, body):
    d = tmp_path / name
    d.mkdir()
    (d / "SKILL.md").write_text(body, encoding="utf-8")
    return d


def test_frontmatter_parses_folded_scalar_and_lists():
    front, body = _parse_frontmatter(_SYNTHETIC)
    assert front["name"] == "demo-skill"
    assert front["description"] == "A folded description that spans two source lines."
    assert front["tags"] == ["alpha", "beta"]
    assert front["languages"] == ["en", "vi"]
    assert "## Workflow" in body


def test_reasoning_question_dsl_parses_stage_condition_and_question():
    body = """## Reasoning Questions
- [surface] Where is the input accepted?
- [fingerprint | if a signal exists] Which database engine is supported by evidence?

## Workflow
1. Continue.
"""
    parsed = _questions(body)
    assert [q.stage for q in parsed] == ["surface", "fingerprint"]
    assert parsed[0].condition == "always"
    assert parsed[1].condition == "if a signal exists"
    assert parsed[1].question.endswith("evidence?")


def test_registry_discovers_and_builds_catalog(tmp_path):
    _skill_dir(tmp_path, "demo-skill", _SYNTHETIC)
    reg = SkillRegistry(tmp_path)
    skills = reg.skills()
    assert len(skills) == 1
    s = skills[0]
    assert s.name == "demo-skill" and s.tags == ["alpha", "beta"]
    catalog = reg.catalog()
    assert catalog[0]["name"] == "demo-skill"
    assert "authorized target" in catalog[0]["trigger"]


def test_load_and_vi_fallback(tmp_path):
    _skill_dir(tmp_path, "demo-skill", _SYNTHETIC)
    (tmp_path / "demo-skill" / "SKILL.vi.md").write_text("noi dung tieng viet", encoding="utf-8")
    _skill_dir(tmp_path, "en-only", _SYNTHETIC.replace("demo-skill", "en-only"))
    reg = SkillRegistry(tmp_path)
    assert "tieng viet" in (reg.load("demo-skill", "vi") or "")
    # A skill with no VI sibling falls back to the English manifest, never errors.
    assert "## Workflow" in (reg.load("en-only", "vi") or "")
    assert reg.load("nope") is None


def test_reasoning_questions_fall_back_to_canonical_manifest(tmp_path):
    canonical = _SYNTHETIC + "\n## Reasoning Questions\n- [surface] What exists?\n"
    _skill_dir(tmp_path, "demo-skill", canonical)
    (tmp_path / "demo-skill" / "SKILL.vi.md").write_text("chưa dịch", encoding="utf-8")
    questions = SkillRegistry(tmp_path).questions("demo-skill", "vi")
    assert len(questions) == 1 and questions[0].question == "What exists?"


def test_skill_exposes_taxonomy_fields_from_bundled_manifest():
    """domain/subdomain/owasp are already in every skill's frontmatter (test_mapping_skills.py
    requires them there) — this checks the loader actually surfaces them on the Skill model."""
    skill = SkillRegistry().get("exploiting-sql-injection")
    assert skill is not None
    assert skill.domain == "web-application-security"
    assert skill.subdomain == "injection"
    assert "A03:2021-Injection" in skill.owasp


def test_bundled_opsec_skills_present():
    """The OPSEC skills ship with the package and are discoverable."""
    names = {s.name for s in SkillRegistry().skills()}
    assert {"red-team-opsec", "opsec-cloud-identity", "opsec-endpoint-evasion"} <= names


def test_load_skill_tool(tmp_path):
    _skill_dir(tmp_path, "demo-skill", _SYNTHETIC)
    reg = ToolRegistry()
    reg.register(LoadSkillTool(SkillRegistry(tmp_path)))
    ok = reg.execute(ToolCall(id="c1", name="load_skill", arguments={"name": "demo-skill"}),
                     ToolContext())
    assert ok.ok and "## Workflow" in ok.log
    bad = reg.execute(ToolCall(id="c2", name="load_skill", arguments={"name": "ghost"}),
                      ToolContext())
    assert not bad.ok and "unknown skill" in bad.log


def test_system_prompt_injects_catalog_only_with_tool():
    config = RunConfig(goal="g", target="http://t")
    with_tool = build_system_prompt(config, [{"name": "load_skill", "description": "d",
                                              "input_schema": {}}])
    without = build_system_prompt(config, [{"name": "http_get", "description": "d",
                                           "input_schema": {}}])
    assert "Available skills" in with_tool
    assert "Available skills" not in without
