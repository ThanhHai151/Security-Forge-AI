"""Expert Supervisor service — orchestrates taxonomy, skills, notebook, and archetype
heuristics into one ``advise()`` call.

Never calls an AI provider and never executes a tool against a target — see the module
docstrings in ``strategy`` and ``ai_framework.notebook`` for why. This is the boundary that
keeps the new advisory flow architecturally separate from the legacy autonomous engine in
``ai_framework.agent``/``backend.service.RunService``.
"""

from __future__ import annotations

from ai_framework.notebook.store import NotebookStore
from ai_framework.research.archetype import ArchetypeStore
from ai_framework.skills.loader import Skill, SkillRegistry
from ai_framework.supervisor import assemble, strategy
from ai_framework.supervisor.contracts import Advice, SessionContext
from ai_framework.taxonomy.tree import Taxonomy


class SupervisorService:
    def __init__(
        self,
        taxonomy: Taxonomy | None = None,
        skills: SkillRegistry | None = None,
        notebooks: NotebookStore | None = None,
        archetypes: ArchetypeStore | None = None,
    ) -> None:
        self.taxonomy = taxonomy or Taxonomy()
        self.skills = skills or SkillRegistry()
        self.notebooks = notebooks or NotebookStore("notebook_store", taxonomy=self.taxonomy)
        self.archetypes = archetypes or ArchetypeStore("archetype_store.json")

    def advise(self, ctx: SessionContext) -> Advice:
        notebook = self.notebooks.get_or_create(ctx.domain)
        if notebook.archetype:
            archetype = self.archetypes.get(notebook.archetype)
        else:
            archetype = self.archetypes.classify(f"{ctx.domain} {ctx.question}")
            if archetype:
                notebook = self.notebooks.set_archetype(ctx.domain, archetype.archetype)

        plan = strategy.build_plan(ctx, self.taxonomy, notebook, archetype)

        if plan:
            # Whatever the plan puts first is what the operator is about to hand Claude Code
            # next — highlight it as the one thing "in progress" until a status is set on it.
            notebook = self.notebooks.set_in_progress(ctx.domain, plan[0].taxonomy_ref)

        node_ids = {step.taxonomy_ref for step in plan}
        selected: list[Skill] = []
        for node_id in node_ids:
            for skill in strategy.skills_for_node(node_id, self.skills):
                if skill.name not in {s.name for s in selected}:
                    selected.append(skill)

        context_block = assemble.render_context_block(
            plan, selected, self.skills, taxonomy=self.taxonomy, notebook=notebook,
            archetype=archetype, scan_mode=ctx.scan_mode, mode=ctx.mode,
        )
        return Advice(
            domain=ctx.domain,
            archetype=archetype.archetype if archetype else "",
            plan=plan,
            skills=assemble.to_skill_refs(selected),
            context_block=context_block,
        )
