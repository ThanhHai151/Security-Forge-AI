"""Deterministic ingestion of an external coding agent's raw output into the Hermes notebook.

No AI-provider call here — the "commentary" the operator sees is Claude Code's own text,
reported back through a couple of documented markers (see
``assemble.render_context_block``'s reporting-format section). sf_agent's job is to store
that text verbatim (``ai_framework.notebook.raw_log.RawLogStore``) and mechanically extract
structured signals from it, never to independently judge, paraphrase, or invent a category.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from ai_framework.notebook.raw_log import RawLogStore
from ai_framework.notebook.store import NotebookStore
from ai_framework.taxonomy.tree import Taxonomy

_CONFIRMED_RE = re.compile(
    r"^\s*CONFIRMED:\s*(.+?)\s*[-—]\s*(.+)$", re.IGNORECASE | re.MULTILINE
)
_NEW_FINDING_RE = re.compile(
    r"^\s*NEW_FINDING_TYPE:\s*(.+?)\s*[-—]\s*JUSTIFICATION:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)


class IngestResult(BaseModel):
    promoted: list[str] = Field(default_factory=list)
    custom_added: list[dict[str, str]] = Field(default_factory=list)


def ingest_output(
    identity: str,
    raw_text: str,
    notebooks: NotebookStore,
    taxonomy: Taxonomy,
    raw_log: RawLogStore | None = None,
) -> IngestResult:
    """Persist ``raw_text`` verbatim, then mechanically fold recognized markers into the
    notebook. Never promotes a node past ``unconfirmed`` — only a human ``set_status`` call
    can mark something ``confirmed``, and a custom node is only ever created from an explicit
    ``NEW_FINDING_TYPE`` marker (never inferred from free text)."""
    if raw_log is not None:
        raw_log.write(identity, raw_text)

    result = IngestResult()

    for match in _CONFIRMED_RE.finditer(raw_text):
        technique_text, evidence = match.group(1), match.group(2)
        hits = taxonomy.match_text(technique_text)
        if not hits:
            continue
        node_id = hits[0].id
        notebooks.ingest_promote(identity, node_id, note=evidence.strip())
        if node_id not in result.promoted:
            result.promoted.append(node_id)

    for match in _NEW_FINDING_RE.finditer(raw_text):
        label, justification = match.group(1).strip(), match.group(2).strip()
        notebooks.add_custom_node(identity, label, justification)
        result.custom_added.append({"label": label, "justification": justification})

    # Fallback: no explicit markers at all — best-effort keyword promotion so pasting plain
    # prose (no marker format) still benefits the notebook a little.
    if not result.promoted and not result.custom_added:
        hits = taxonomy.match_text(raw_text)
        if hits:
            node_id = hits[0].id
            notebooks.ingest_promote(
                identity, node_id, note="keyword match (no explicit marker used)"
            )
            result.promoted.append(node_id)

    return result
