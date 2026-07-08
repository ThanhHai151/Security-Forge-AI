"""Data contracts for the Hermes notebook — a per-domain confirmed/unconfirmed/untested tree.

Distinct from ``ai_framework.agent.campaign``'s 4-state coverage map, which an autonomous
run derives from its own transcript. The notebook is driven by a human operator reading an
*external* coding agent's output, so it deliberately never auto-promotes a node to
``confirmed`` on its own — see ``store.py``'s ``ingest_promote`` vs. ``set_status``.

Red-team only: a domain can be a child of another (``parent_domain``), so a root domain can
nest discovered subdomains, each with its own independent notebook. Source-code review lives
in the separate Defense feature and does not feed into this notebook.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(UTC)


class NodeStatus(StrEnum):
    untested = "untested"
    unconfirmed = "unconfirmed"
    confirmed = "confirmed"


class NotebookNode(BaseModel):
    """One taxonomy technique's (or custom finding's) status for a specific domain."""

    id: str  # taxonomy technique node id (e.g. "sql_injection") or "custom:<slug>"
    status: NodeStatus = NodeStatus.untested
    note: str = ""
    # Per-finding impact, supplied by whoever confirms it (the external agent via a
    # `[severity]` ingest marker, or a human) — "" means "unknown, fall back to the class
    # default". SecForge never executes, so it can't derive this itself; the reporting layer
    # (report/sarif.py) uses it to score this instance instead of the vuln class's generic
    # severity. One of: critical | high | medium | low | info (or "").
    severity: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    updated_by: str = ""  # "user" | "ingest"
    updated_at: datetime = Field(default_factory=_now)
    # Whichever node the operator/agent is actively working on right now (at most one True
    # per notebook — see NotebookStore.set_in_progress). Purely a UI highlight, not a status.
    in_progress: bool = False
    # A node outside the static taxonomy, added only from an explicit external-agent marker
    # (never inferred) — see ai_framework.supervisor.ingest. Filed under a synthetic "others"
    # category in NotebookStore.tree_view; `justification` is that marker's required reason.
    is_custom: bool = False
    justification: str = ""


class ChainLink(BaseModel):
    """A manually-recorded exploit-chain step from one node to another within a domain."""

    from_node: str
    to_node: str
    note: str = ""


class Notebook(BaseModel):
    """The per-domain notebook: one entry per taxonomy technique, plus domain metadata."""

    id: str
    domain: str
    parent_domain: str = ""  # "" = a root domain; otherwise the parent's `domain` value
    archetype: str = ""
    nodes: dict[str, NotebookNode] = Field(default_factory=dict)
    chains: list[ChainLink] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
