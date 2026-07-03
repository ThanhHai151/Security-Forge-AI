"""Persistent Hermes notebook store — one JSON file per domain (mirrors ``CampaignStore``).

A *new* domain always starts a fresh notebook: every taxonomy technique seeded as
``untested``, no node/status copied from any other domain. Cross-domain reuse only ever
happens at the archetype-heuristic layer (``ai_framework.research.archetype``), which
carries *priorities*, never specific findings or statuses.

Red-team only: a domain can be nested under a ``parent_domain`` so a root target can carry
discovered subdomains, each with its own independent notebook. Source-code review lives in
the separate Defense feature and does not feed into this notebook.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from ai_framework.notebook.contracts import ChainLink, NodeStatus, Notebook, NotebookNode
from ai_framework.taxonomy.tree import Taxonomy


def _domain_key(domain: str) -> str:
    """Filesystem-safe stem for a domain string (a bare host or full URL)."""
    host = urlparse(domain if "://" in domain else f"http://{domain}").hostname or domain
    return re.sub(r"[^a-z0-9.-]+", "_", host.lower().strip()) or "unknown"


def _slugify_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-") or "finding"


class NotebookStore:
    def __init__(self, directory: str | Path, taxonomy: Taxonomy | None = None) -> None:
        self.dir = Path(directory)
        self.taxonomy = taxonomy or Taxonomy()
        # The backend runs a ThreadingHTTPServer, so two requests touching the same brand-new
        # domain (e.g. the sidebar's tree + notebook GETs firing together on first select) can
        # both see no file yet and race to create+save it. A shared tmp filename made that race
        # crash outright on Windows (PermissionError/FileNotFoundError on the .tmp -> .json
        # rename); this lock serializes every write so the race is at worst a harmless
        # duplicate save instead of a corrupted rename.
        self._write_lock = threading.Lock()

    def _path(self, domain: str) -> Path:
        return self.dir / f"{_domain_key(domain)}.json"

    def load(self, domain: str) -> Notebook | None:
        path = self._path(domain)
        if not path.is_file():
            return None
        return Notebook.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, notebook: Notebook) -> None:
        with self._write_lock:
            self.dir.mkdir(parents=True, exist_ok=True)
            path = self._path(notebook.domain)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(notebook.model_dump_json(), encoding="utf-8")
            tmp.replace(path)

    def get_or_create(self, domain: str, parent_domain: str = "") -> Notebook:
        """Fetch a domain's notebook, seeding it fresh the first time it's seen.

        ``parent_domain`` only takes effect on first creation — a returning domain keeps
        whatever it was already stored as.
        """
        existing = self.load(domain)
        if existing is not None:
            return existing
        nodes = {n.id: NotebookNode(id=n.id) for n in self.taxonomy.technique_nodes()}
        notebook = Notebook(
            id=_domain_key(domain), domain=domain, parent_domain=parent_domain, nodes=nodes
        )
        self.save(notebook)
        return notebook

    def set_status(
        self,
        domain: str,
        node_id: str,
        status: NodeStatus,
        note: str = "",
        updated_by: str = "user",
    ) -> Notebook:
        notebook = self.get_or_create(domain)
        node = notebook.nodes.get(node_id) or NotebookNode(id=node_id)
        node.status = status
        if note:
            node.note = note
        node.updated_by = updated_by
        node.updated_at = datetime.now(UTC)
        node.in_progress = False  # a manual status change means testing this node concluded
        notebook.nodes[node_id] = node
        notebook.updated_at = node.updated_at
        self.save(notebook)
        return notebook

    def ingest_promote(self, domain: str, node_id: str, note: str = "") -> Notebook:
        """Auto-promote ``untested -> unconfirmed`` from parsed external-agent output.

        Never sets ``confirmed`` and never downgrades an existing status — SecForge no
        longer executes or verifies anything itself in this flow, so it has no way to
        adversarially confirm impact. Confirming is always a human ``set_status`` call.
        """
        notebook = self.get_or_create(domain)
        node = notebook.nodes.get(node_id)
        if node is not None and node.status != NodeStatus.untested:
            return notebook
        return self.set_status(
            domain, node_id, NodeStatus.unconfirmed, note=note, updated_by="ingest"
        )

    def link_finding(self, domain: str, node_id: str, finding_id: str) -> Notebook:
        notebook = self.get_or_create(domain)
        node = notebook.nodes.get(node_id) or NotebookNode(id=node_id)
        if finding_id not in node.finding_ids:
            node.finding_ids.append(finding_id)
        notebook.nodes[node_id] = node
        self.save(notebook)
        return notebook

    def set_archetype(self, domain: str, archetype: str) -> Notebook:
        notebook = self.get_or_create(domain)
        notebook.archetype = archetype
        self.save(notebook)
        return notebook

    def set_in_progress(self, domain: str, node_id: str) -> Notebook:
        """Mark ``node_id`` as the one thing currently being tested on this domain.

        At most one node is ``in_progress`` per notebook — any other node's flag is cleared.
        Purely a UI highlight; it never changes ``status``.
        """
        notebook = self.get_or_create(domain)
        for nid, node in notebook.nodes.items():
            node.in_progress = nid == node_id
        if node_id not in notebook.nodes:
            new_node = NotebookNode(id=node_id, in_progress=True)
            notebook.nodes[node_id] = new_node
        self.save(notebook)
        return notebook

    def add_custom_node(
        self,
        domain: str,
        label: str,
        justification: str,
        status: NodeStatus = NodeStatus.unconfirmed,
    ) -> Notebook:
        """File a vulnerability class outside the static taxonomy under "Others".

        Only ever called from an explicit, verbatim marker in an external agent's output
        (see ``ai_framework.supervisor.ingest``) — ``justification`` is that marker's
        required reason, never inferred here.
        """
        notebook = self.get_or_create(domain)
        node_id = f"custom:{_slugify_label(label)}"
        node = notebook.nodes.get(node_id) or NotebookNode(id=node_id, is_custom=True)
        node.status = status
        node.note = label
        node.justification = justification
        node.updated_by = "ingest"
        node.updated_at = datetime.now(UTC)
        notebook.nodes[node_id] = node
        notebook.updated_at = node.updated_at
        self.save(notebook)
        return notebook

    def add_chain(self, domain: str, from_node: str, to_node: str, note: str = "") -> Notebook:
        notebook = self.get_or_create(domain)
        notebook.chains.append(ChainLink(from_node=from_node, to_node=to_node, note=note))
        self.save(notebook)
        return notebook

    def add_child(self, parent_domain: str, child_domain: str) -> Notebook:
        """Attach a discovered subdomain under its parent."""
        self.get_or_create(parent_domain)  # ensure the parent exists too
        return self.get_or_create(child_domain, parent_domain=parent_domain)

    def delete(self, domain: str) -> bool:
        """Permanently remove a domain's notebook file. Returns False if it didn't exist.

        Does not cascade to subdomains — a child whose ``parent_domain`` no longer resolves
        to an existing notebook simply surfaces as its own root in ``roots_and_children()``
        rather than being deleted too.
        """
        with self._write_lock:
            path = self._path(domain)
            if not path.is_file():
                return False
            path.unlink()
            return True

    def tree_view(self, domain: str) -> list[dict]:
        """Taxonomy tree merged with this domain's per-node status, for the sidebar UI.

        Any node id outside the static taxonomy (``is_custom``) is appended under a
        synthesized "Others" category rather than dropped.
        """
        notebook = self.get_or_create(domain)
        tree = self.taxonomy.tree()
        known_ids: set[str] = set()
        for category in tree:
            children = category["children"]
            assert isinstance(children, list)
            for child in children:
                known_ids.add(child["id"])
                node = notebook.nodes.get(child["id"])
                child["status"] = node.status.value if node else NodeStatus.untested.value
                child["note"] = node.note if node else ""
                child["in_progress"] = bool(node and node.in_progress)
                child["justification"] = ""

        custom = [n for nid, n in notebook.nodes.items() if nid not in known_ids and n.is_custom]
        if custom:
            tree.append(
                {
                    "id": "others",
                    "label": "Others",
                    "children": [
                        {
                            "id": n.id,
                            "label": n.note or n.id,
                            "catalog_ref": "",
                            "status": n.status.value,
                            "note": n.note,
                            "in_progress": n.in_progress,
                            "justification": n.justification,
                        }
                        for n in custom
                    ],
                }
            )
        return tree

    def roots_and_children(self) -> list[dict]:
        """Nested root -> subdomain summaries for the sidebar's target tree."""
        flat = self.list_domains()
        by_domain = {d["domain"]: {**d, "children": []} for d in flat}
        roots: list[dict] = []
        for d in flat:
            node = by_domain[d["domain"]]
            parent = d.get("parent_domain") or ""
            if parent and parent in by_domain:
                by_domain[parent]["children"].append(node)
            else:
                roots.append(node)
        return roots

    def list_domains(self) -> list[dict]:
        """Lightweight summaries (newest first) for a domain-history sidebar."""
        if not self.dir.is_dir():
            return []
        out: list[dict] = []
        for path in sorted(self.dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            nodes = data.get("nodes", {})
            confirmed = sum(1 for n in nodes.values() if n.get("status") == "confirmed")
            out.append(
                {
                    "domain": data.get("domain", path.stem),
                    "parent_domain": data.get("parent_domain", ""),
                    "archetype": data.get("archetype", ""),
                    "confirmed": confirmed,
                    "total": len(nodes),
                    "updated_at": data.get("updated_at", ""),
                }
            )
        return out
