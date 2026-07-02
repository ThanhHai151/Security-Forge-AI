"""Map an offensive :class:`Finding` to concrete fix guidance from the knowledge base.

A finding the agent records (title + severity + evidence) tells you *what* is wrong; the
operator still has to look up *how* to fix it. This resolver closes that gap without a model
call: it matches a finding to its vulnerability class in the bundled catalog — by ``kb_ref``,
by ``tags``, or by keywords in the title — and returns that class's **"Defenses"** section, the
same curated remediation text the defensive reviewer surfaces. So the pentest report can carry
weakness → fix inline, exactly like ``defense/``.
"""

from __future__ import annotations

from ai_framework.notes.contracts import Finding
from knowledge_base.index import KnowledgeBase, section

# Technique shorthand (how the agent tends to tag findings) → the catalog slug that documents it.
# Only slugs that actually exist in the catalog are ever returned (guarded against the live set).
_ALIASES: dict[str, str] = {
    "sqli": "sql_injection", "sql": "sql_injection",
    "idor": "broken_access_control", "bola": "broken_access_control",
    "access_control": "broken_access_control", "authz": "broken_access_control",
    "rce": "os_command_injection", "command_injection": "os_command_injection",
    "cmdi": "os_command_injection", "os_command": "os_command_injection",
    "lfi": "path_traversal", "rfi": "path_traversal", "traversal": "path_traversal",
    "deserialization": "insecure_deserialization", "deser": "insecure_deserialization",
    "nosql": "nosql_injection",
    "host_header": "http_host_header",
    "upload": "file_upload",
    "auth": "broken_authentication", "authn": "broken_authentication",
    "authentication": "broken_authentication", "credential": "broken_authentication",
    "info_disclosure": "information_disclosure", "disclosure": "information_disclosure",
    "leak": "information_disclosure",
    "smuggling": "http_request_smuggling", "desync": "http_request_smuggling",
    "cache_poisoning": "web_cache_poisoning", "cache_deception": "web_cache_deception",
    "prototype": "prototype_pollution",
    "race": "race_condition", "toctou": "race_condition",
    "llm": "llm_attacks", "prompt_injection": "llm_attacks",
    "ws": "websockets", "websocket": "websockets",
    "template_injection": "ssti",
}


def _norm(token: str) -> str:
    """Fold a tag/title token to the catalog's slug shape (lower, underscore-separated)."""
    return token.strip().lower().replace(" ", "_").replace("-", "_")


class Remediator:
    """Resolves findings to catalog fix guidance, caching the ``Defenses`` text per class."""

    def __init__(self, kb: KnowledgeBase) -> None:
        self._kb = kb
        self._slugs = {e.id for e in kb.all()}
        self._guidance: dict[str, str] = {}

    def slug_for(self, finding: Finding) -> str:
        """The catalog slug that best matches this finding, or ``""`` if none applies."""
        # 1) An explicit reference or tag — exact slug, or a known shorthand alias.
        for raw in [finding.kb_ref, *finding.tags]:
            if not raw:
                continue
            n = _norm(raw)
            if n in self._slugs:
                return n
            alias = _ALIASES.get(n)
            if alias and alias in self._slugs:
                return alias
        # 2) A slug's name appearing in the title (longest slug first so "sql_injection" wins).
        title = _norm(finding.title)
        squashed = title.replace("_", "")
        for slug in sorted(self._slugs, key=len, reverse=True):
            if slug in title or slug.replace("_", "") in squashed:
                return slug
        # 3) A shorthand keyword appearing in the title.
        for key, slug in _ALIASES.items():
            if key in title and slug in self._slugs:
                return slug
        return ""

    def guidance(self, slug: str) -> str:
        """The catalog ``Defenses`` section for a slug (cached)."""
        if slug not in self._guidance:
            self._guidance[slug] = section(self._kb.body(slug), "Defenses")
        return self._guidance[slug]

    def for_finding(self, finding: Finding) -> tuple[str, str]:
        """``(slug, guidance)`` for a finding — both empty when nothing in the catalog matches."""
        slug = self.slug_for(finding)
        return (slug, self.guidance(slug)) if slug else ("", "")
