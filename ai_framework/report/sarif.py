"""Export a domain notebook as SARIF 2.1.0 for CI upload (GitHub code scanning, etc.).

The advisory flow records confirmed/unconfirmed vulnerability *classes* per domain in the
Hermes notebook — not per-line source findings, because SecForge never executes against the
target itself. This renders those nodes into SARIF so a CI pipeline can surface them like any
other scanner, mirroring the reference tool's ``findings.sarif`` output. Fully deterministic:
no AI-provider call, no target access.

Each confirmed/unconfirmed node becomes one SARIF result keyed to a per-technique rule; the
rule's CWE / OWASP / ATT&CK / WSTG references come from ``vuln_search.mapping`` and STRIDE legs
from the table below. ``security-severity`` is a coarse per-class heuristic — the notebook
carries no CVSS (unlike the reference tool, where the model scores each finding), so treat it
as class-inherent risk, not a validated CVSS for this specific instance. ``untested`` nodes
are omitted; an all-untested notebook still yields a valid (empty-results) SARIF run so a
clean scan can auto-resolve stale code-scanning alerts.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from ai_framework.notebook.contracts import NodeStatus
from vuln_search.mapping import mapping_for

if TYPE_CHECKING:
    from ai_framework.notebook.contracts import Notebook, NotebookNode
    from ai_framework.taxonomy.tree import Taxonomy

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_NAME = "SecForge"
_TOOL_URI = "https://github.com/"  # placeholder home; overridable is not needed for CI upload

# Coarse class-inherent severity (0.0-10.0), used for SARIF ``security-severity``. The notebook
# has no CVSS, so these are documented defaults by blast radius, not per-instance scores.
_SEVERITY_BY_NODE: dict[str, float] = {
    "os_command_injection": 9.1,
    "insecure_deserialization": 9.0,
    "sql_injection": 8.8,
    "ssti": 8.6,
    "nosql_injection": 8.2,
    "broken_access_control": 8.2,
    "broken_authentication": 8.1,
    "ssrf": 8.0,
    "xxe": 7.7,
    "jwt": 7.5,
    "file_upload": 7.5,
    "http_request_smuggling": 7.3,
    "oauth": 7.1,
    "path_traversal": 7.0,
    "prototype_pollution": 6.5,
    "web_cache_poisoning": 6.5,
    "csrf": 6.5,
    "llm_attacks": 6.5,
    "race_condition": 6.0,
    "api_security": 6.0,
    "http_host_header": 6.0,
    "xss": 6.1,
    "dom_based": 6.1,
    "cors": 5.5,
    "graphql": 5.5,
    "websockets": 5.5,
    "web_cache_deception": 5.3,
    "information_disclosure": 5.3,
    "clickjacking": 4.3,
}
_DEFAULT_SEVERITY = 5.0

# When a finding carries an explicit per-instance severity (from whoever confirmed it — see
# NotebookNode.severity), it overrides the class default: a token-leak filed as "critical"
# scores 9.5, not information_disclosure's generic 5.3.
_SEVERITY_LABEL_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.5}
_SEVERITY_LABEL_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note",
}

# STRIDE leg(s) per catalog slug: S(poofing) T(ampering) R(epudiation) I(nfo disclosure)
# D(enial of service) E(levation of privilege). Default ("T", "I") for anything unmapped,
# matching the reference tool's fallback.
_STRIDE_BY_NODE: dict[str, tuple[str, ...]] = {
    "sql_injection": ("T", "I"),
    "nosql_injection": ("T", "I"),
    "os_command_injection": ("E", "T"),
    "ssti": ("E", "T"),
    "xxe": ("I", "D"),
    "path_traversal": ("I",),
    "xss": ("T", "S"),
    "dom_based": ("T", "S"),
    "csrf": ("S", "T"),
    "clickjacking": ("T",),
    "cors": ("I",),
    "prototype_pollution": ("T", "E"),
    "broken_authentication": ("S", "E"),
    "jwt": ("S", "E"),
    "oauth": ("S", "E"),
    "broken_access_control": ("E", "I"),
    "ssrf": ("I",),
    "http_host_header": ("T", "S"),
    "http_request_smuggling": ("T", "I"),
    "web_cache_deception": ("I",),
    "web_cache_poisoning": ("T", "I"),
    "api_security": ("I", "E"),
    "graphql": ("I",),
    "websockets": ("T", "I"),
    "llm_attacks": ("T", "I"),
    "file_upload": ("E", "T"),
    "race_condition": ("T",),
    "information_disclosure": ("I",),
    "insecure_deserialization": ("E", "T"),
}
_DEFAULT_STRIDE: tuple[str, ...] = ("T", "I")

_LEVEL_BY_STATUS = {NodeStatus.confirmed: "error", NodeStatus.unconfirmed: "warning"}


def _cwe_num(cwe: str) -> str:
    """'CWE-89' / 'cwe:89' / '89' -> '89' (best effort; '' if not numeric)."""
    digits = "".join(ch for ch in cwe if ch.isdigit())
    return digits


def _label_for(node_id: str, node: NotebookNode, taxonomy: Taxonomy | None) -> str:
    if node.is_custom:
        return node.note or node_id
    if taxonomy is not None:
        found = taxonomy.get(node_id)
        if found is not None:
            return found.label
    return node_id


def _severity_score(node_id: str, severity: str) -> float:
    """Per-instance severity wins over the class default when present."""
    if severity in _SEVERITY_LABEL_SCORE:
        return _SEVERITY_LABEL_SCORE[severity]
    return _SEVERITY_BY_NODE.get(node_id, _DEFAULT_SEVERITY)


def _rule_for(node_id: str, label: str, severity: str = "") -> dict[str, Any]:
    m = mapping_for(node_id)
    cwes: list[str] = list(m.get("cwe") or [])
    owasp = str(m.get("owasp") or "")
    attack: list[str] = list(m.get("attack") or [])
    wstg: list[str] = list(m.get("wstg") or [])
    stride = _STRIDE_BY_NODE.get(node_id, _DEFAULT_STRIDE)

    tags = ["security"]
    tags += [f"external/cwe/{c}" for c in cwes]
    if owasp:
        tags.append(f"owasp/{owasp}")
    tags += [f"external/attack/{a}" for a in attack]
    tags += [f"external/wstg/{w}" for w in wstg]
    tags += [f"stride/{leg}" for leg in stride]

    help_uri = ""
    if cwes:
        num = _cwe_num(cwes[0])
        if num:
            help_uri = f"https://cwe.mitre.org/data/definitions/{num}.html"

    rule: dict[str, Any] = {
        "id": node_id,
        "name": "".join(part.capitalize() for part in node_id.split("_")),
        "shortDescription": {"text": label},
        "properties": {
            "security-severity": f"{_severity_score(node_id, severity):.1f}",
            "tags": tags,
        },
    }
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def _result_for(node_id: str, node: NotebookNode, label: str, domain: str) -> dict[str, Any]:
    m = mapping_for(node_id)
    status = node.status.value
    text = f"{label} — {status} on {domain}."
    if node.note:
        text += f" {node.note}"
    if node.is_custom and node.justification:
        text += f" (custom finding: {node.justification})"
    fingerprint = hashlib.sha256(f"{domain}:{node_id}".encode()).hexdigest()[:16]
    # An explicit per-finding severity sets the SARIF level (critical/high -> error, etc.);
    # otherwise fall back to the status (confirmed -> error, unconfirmed -> warning).
    level = _SEVERITY_LABEL_LEVEL.get(node.severity, _LEVEL_BY_STATUS.get(node.status, "warning"))
    return {
        "ruleId": node_id,
        "level": level,
        "message": {"text": text},
        "locations": [
            {"logicalLocations": [{"name": domain, "kind": "resource"}]},
        ],
        "partialFingerprints": {"secforgePrimary": fingerprint},
        "properties": {
            "status": status,
            "severity": node.severity,
            "taxonomy_ref": node_id,
            "is_custom": node.is_custom,
            "cwe": list(m.get("cwe") or []),
            "owasp": str(m.get("owasp") or ""),
            "finding_ids": list(node.finding_ids),
        },
    }


def notebook_to_sarif(
    notebook: Notebook,
    *,
    taxonomy: Taxonomy | None = None,
    tool_version: str = "0.0.1",
) -> dict[str, Any]:
    """Render one domain notebook's confirmed/unconfirmed nodes as a SARIF 2.1.0 document."""
    reported = {NodeStatus.confirmed, NodeStatus.unconfirmed}
    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    results: list[dict[str, Any]] = []

    for node_id, node in notebook.nodes.items():
        if node.status not in reported:
            continue
        label = _label_for(node_id, node, taxonomy)
        if node_id not in seen_rules:
            rules.append(_rule_for(node_id, label, node.severity))
            seen_rules.add(node_id)
        results.append(_result_for(node_id, node, label, notebook.domain))

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _TOOL_URI,
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"domain": notebook.domain},
            }
        ],
    }
