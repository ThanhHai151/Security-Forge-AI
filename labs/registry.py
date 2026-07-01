"""Lab registry — discovers labs and dispatches requests to them.

'Extensibility = add a file': a new :class:`~labs.base.Lab` registered here appears in the
listing and is reachable, no other wiring required.
"""

from __future__ import annotations

from labs.base import Lab, LabMeta, LabRequest, LabResponse
from labs.builtin import builtin_labs


class LabRegistry:
    def __init__(self) -> None:
        self._labs: dict[str, Lab] = {}

    def register(self, lab: Lab) -> None:
        self._labs[lab.slug] = lab

    def get(self, slug: str) -> Lab | None:
        return self._labs.get(slug)

    def list(self) -> list[LabMeta]:
        return [lab.meta() for lab in self._labs.values()]

    def handle(self, slug: str, req: LabRequest) -> LabResponse:
        lab = self._labs.get(slug)
        if lab is None:
            return LabResponse(status=404, body="<p>Unknown lab.</p>")
        return lab.handle(req)

    def reset(self, slug: str) -> bool:
        lab = self._labs.get(slug)
        if lab is None:
            return False
        lab.reset()
        return True


def default_registry() -> LabRegistry:
    reg = LabRegistry()
    for lab in builtin_labs():
        reg.register(lab)
    return reg
