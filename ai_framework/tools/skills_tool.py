"""``load_skill`` — on-demand retrieval of a skill's full procedure (progressive disclosure).

The system prompt only lists the skill *catalog* (name + trigger); when a trigger matches what
the agent is seeing, it calls this tool to pull the full ``SKILL.md`` into context. Local and
always safe — it reads bundled manifest files, touches no network, changes no state.
"""

from __future__ import annotations

from typing import Any

from ai_framework.skills.loader import SkillRegistry
from ai_framework.tools.base import ToolContext


class LoadSkillTool:
    name = "load_skill"
    description = (
        "Load a security skill's full procedure by name (from the catalog in the system prompt) "
        "when its trigger matches what you're seeing. Returns When-to-Use / Prerequisites / "
        "Workflow / Verification. Local and always safe."
    )
    touches_network = False
    mutating = False

    def __init__(self, registry: SkillRegistry | None = None) -> None:
        self._registry = registry or SkillRegistry()

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Skill name from the catalog."},
                "locale": {"type": "string", "description": "en (default) or vi."},
            },
            "required": ["name"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        name = str(args.get("name", "")).strip()
        locale = str(args.get("locale") or "en").strip() or "en"
        if not name:
            raise ValueError("missing skill 'name'")
        text = self._registry.load(name, locale)
        if text is None:
            available = ", ".join(s["name"] for s in self._registry.catalog()) or "(none)"
            raise ValueError(f"unknown skill: {name!r}. Available: {available}")
        return text
