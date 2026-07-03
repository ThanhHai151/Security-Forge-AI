"""Deterministic strategy/skill-matching for the Expert Supervisor.

No AI-provider call here, on purpose: the whole point of the pivot away from an autonomous
agent is that SecForge stops spending model calls deciding what to do next. Claude Code (or
whichever coding agent the operator drives) has the real reasoning budget and the full
target/source context; this module's job is cheap, deterministic routing so it doesn't have
to guess where to start.
"""

from __future__ import annotations

from ai_framework.notebook.contracts import NodeStatus, Notebook
from ai_framework.research.archetype import ArchetypeHeuristic
from ai_framework.skills.loader import Skill, SkillRegistry
from ai_framework.supervisor.contracts import PlanStep, SessionContext
from ai_framework.taxonomy.tree import Taxonomy
from ai_framework.taxonomy.whitebox_signals import rank_files, signals_for

MAX_PLAN_STEPS = 8

# Skill directory -> taxonomy technique node id(s). Explicit and small (13 bundled skills)
# beats fuzzy matching on tags/subdomain, which drift today (e.g. exploiting-xss's
# frontmatter tags "injection" even though the catalog groups XSS under Client-side).
SKILL_TAXONOMY_MAP: dict[str, tuple[str, ...]] = {
    "attacking-authentication": ("broken_authentication",),
    "attacking-jwt": ("jwt",),
    "exploiting-command-injection": ("os_command_injection",),
    "exploiting-deserialization": ("insecure_deserialization",),
    "exploiting-file-upload": ("file_upload",),
    "exploiting-idor": ("broken_access_control",),
    "exploiting-sql-injection": ("sql_injection", "nosql_injection"),
    "exploiting-ssrf": ("ssrf",),
    "exploiting-ssti": ("ssti",),
    "exploiting-xss": ("xss", "dom_based"),
    "exploiting-xxe": ("xxe",),
}


def skills_for_node(node_id: str, registry: SkillRegistry) -> list[Skill]:
    by_dir = {s.dir: s for s in registry.skills()}
    return [
        by_dir[dir_name]
        for dir_name, node_ids in SKILL_TAXONOMY_MAP.items()
        if node_id in node_ids and dir_name in by_dir
    ]


def _status_rank(status: NodeStatus) -> int:
    """Lower sorts first: untested leads before unconfirmed before confirmed/dead-end."""
    return {NodeStatus.untested: 0, NodeStatus.unconfirmed: 1, NodeStatus.confirmed: 2}[status]


def _node_status(notebook: Notebook | None, node_id: str) -> NodeStatus:
    if notebook is not None and node_id in notebook.nodes:
        return notebook.nodes[node_id].status
    return NodeStatus.untested


def rank_technique_nodes(
    ctx: SessionContext,
    taxonomy: Taxonomy,
    notebook: Notebook | None,
    archetype: ArchetypeHeuristic | None,
) -> list[str]:
    """Ordered technique node ids: text match first, then notebook status, then archetype boost."""
    matched = [n.id for n in taxonomy.match_text(ctx.question)]
    if not matched:
        # No specific technique named in the question — fall back to every technique so
        # notebook status / archetype boosting still produce a sensible general order.
        matched = [n.id for n in taxonomy.technique_nodes()]
    boosted = set(archetype.priority_nodes) if archetype else set()

    def sort_key(node_id: str) -> tuple[int, int, int]:
        return (
            0 if node_id in boosted else 1,
            _status_rank(_node_status(notebook, node_id)),
            matched.index(node_id) if node_id in matched else len(matched),
        )

    return sorted(set(matched) | boosted, key=sort_key)


def build_plan(
    ctx: SessionContext,
    taxonomy: Taxonomy,
    notebook: Notebook | None,
    archetype: ArchetypeHeuristic | None,
) -> list[PlanStep]:
    """Rank techniques, then attach whitebox/blackbox reasoning for the top candidates."""
    node_ids = rank_technique_nodes(ctx, taxonomy, notebook, archetype)
    steps: list[PlanStep] = []
    for node_id in node_ids:
        if len(steps) >= MAX_PLAN_STEPS:
            break
        node = taxonomy.get(node_id)
        if node is None:
            continue
        if _node_status(notebook, node_id) == NodeStatus.confirmed:
            continue  # already confirmed on this domain — no need to re-investigate

        if ctx.mode == "whitebox" and ctx.project_path:
            files = rank_files(ctx.project_path, node_id)
            if files:
                top = ", ".join(f"{f['path']} ({f['hits']} hits)" for f in files[:5])
                reasoning = f"grep signals for {node.label} concentrate in: {top}"
            elif signals_for(node_id):
                reasoning = (
                    f"no strong grep signal for {node.label} in this project — "
                    "check manually, lower priority"
                )
            else:
                reasoning = f"no static signal table for {node.label} yet — inspect by hand"
        else:
            reasoning = (
                f"blackbox: probe the parameters/endpoints most associated with {node.label}"
            )

        if archetype and node_id in archetype.priority_nodes:
            reasoning += f"; boosted for archetype '{archetype.label}': {archetype.rationale}"

        steps.append(
            PlanStep(
                order=len(steps) + 1,
                action=f"Investigate {node.label}",
                reasoning=reasoning,
                taxonomy_ref=node_id,
            )
        )
    return steps
