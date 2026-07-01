"""Lab protocol + request/response shapes.

A lab is transport-agnostic: it takes a :class:`LabRequest` and returns a :class:`LabResponse`,
so the same logic is exercised by unit tests (no sockets) and by the localhost server. State
lives in plain Python structures the lab owns; :meth:`Lab.reset` restores a clean slate.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class LabRequest(BaseModel):
    method: str = "GET"
    path: str = "/"  # path *within* the lab (the ``/labs/<slug>`` prefix is stripped)
    query: dict[str, str] = Field(default_factory=dict)
    body: dict[str, str] = Field(default_factory=dict)


class LabResponse(BaseModel):
    status: int = 200
    body: str = ""
    solved: bool = False
    note: str = ""  # hint / feedback shown alongside the response
    content_type: str = "text/html; charset=utf-8"


class LabMeta(BaseModel):
    """Listing metadata — what the catalog/Labs tab shows without launching anything."""

    slug: str
    title: str
    category: str
    kb_id: str  # links to the knowledge-base class
    skill: str  # links to the matching skill
    difficulty: str
    description: str
    solved: bool = False


@runtime_checkable
class Lab(Protocol):
    slug: str
    title: str
    category: str
    kb_id: str
    skill: str
    difficulty: str
    description: str
    solved: bool

    def reset(self) -> None:
        """Restore clean, unsolved in-memory state."""
        ...

    def handle(self, req: LabRequest) -> LabResponse:
        """Process a request against the fake target."""
        ...

    def meta(self) -> LabMeta:
        ...


class BaseLab:
    """Shared metadata + a default :meth:`meta`. Concrete labs set the class attributes."""

    slug = ""
    title = ""
    category = ""
    kb_id = ""
    skill = "ai_framework/skills/"
    difficulty = "apprentice"
    description = ""

    def __init__(self) -> None:
        self.solved = False
        self.reset()

    def reset(self) -> None:  # overridden to also reset fake data
        self.solved = False

    def meta(self) -> LabMeta:
        return LabMeta(
            slug=self.slug,
            title=self.title,
            category=self.category,
            kb_id=self.kb_id,
            skill=self.skill,
            difficulty=self.difficulty,
            description=self.description,
            solved=self.solved,
        )
