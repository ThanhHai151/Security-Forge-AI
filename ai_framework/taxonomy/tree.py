"""Vulnerability taxonomy — one shared tree of categories -> techniques.

The source of truth is ``vuln_search/catalog/INDEX.md``: it already groups the 29 catalog
entries under six ``## Heading`` categories (Injection, Client-side, Authentication &
identity, Server-side & infrastructure, APIs & modern, Other). This module parses that
structure once so the Expert Supervisor, the Hermes notebook, and skill matching all
address the same vocabulary instead of each inventing their own.

Keyword matching reuses the spirit of ``ai_framework.agent.campaign.TECHNIQUES`` but is
re-keyed onto the catalog's own slugs (they don't always line up, e.g. campaign's "sqli"
vs. the catalog's "sql_injection") and extended with Vietnamese aliases, since a
supervisor question may arrive in either language.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from pydantic import BaseModel, Field

_HEADING_RE = re.compile(r"^##\s+(.+)$")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def _slugify(label: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    return s


def normalize_text(text: str) -> str:
    """Lowercase + strip Vietnamese diacritics, so keyword matching tolerates unaccented
    input (common on ASCII-only keyboards/IMEs) as well as fully-accented Vietnamese."""
    decomposed = unicodedata.normalize("NFD", text.lower())
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return stripped.replace("đ", "d")


def _default_index_path() -> Path:
    return Path(__file__).resolve().parents[2] / "vuln_search" / "catalog" / "INDEX.md"


# Bilingual (EN/VI) keyword aliases per catalog slug, used to match a free-text question to
# a technique node. Not exhaustive — extend as real queries reveal gaps.
TECHNIQUE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "sql_injection": (
        "sql injection", "sqli", "sqlmap", "union select", "' or 1=1", "boolean-based",
        "lỗi sql injection", "lỗi sql", "tiêm sql", "chèn sql",
    ),
    "nosql_injection": (
        "nosql", "nosql injection", "$where", "$ne", "mongodb", "tiêm nosql",
    ),
    "os_command_injection": (
        "os command injection", "command injection", "os command", "rce",
        "remote code execution", "tiêm lệnh hệ điều hành", "chèn lệnh", "thực thi lệnh",
    ),
    "ssti": (
        "ssti", "server-side template injection", "template injection", "{{7*7}}", "jinja",
        "chèn template", "tiêm mẫu",
    ),
    "xxe": (
        "xxe", "xml external entity", "<!entity", "doctype", "thực thể xml ngoài",
    ),
    "path_traversal": (
        "path traversal", "directory traversal", "../", "duyệt đường dẫn", "duyệt thư mục",
    ),
    "xss": (
        "xss", "cross-site scripting", "<script", "reflected xss", "stored xss",
        "tiêm mã xss", "kịch bản chéo trang",
    ),
    "dom_based": (
        "dom-based", "dom xss", "dom clobbering", "dom",
    ),
    "csrf": (
        "csrf", "cross-site request forgery", "anti-csrf", "giả mạo yêu cầu chéo trang",
    ),
    "clickjacking": (
        "clickjacking", "x-frame-options", "click giả mạo", "nhấp chuột giả mạo",
    ),
    "cors": (
        "cors", "access-control-allow-origin", "cross-origin", "cấu hình cors sai",
    ),
    "prototype_pollution": (
        "prototype pollution", "__proto__", "ô nhiễm prototype",
    ),
    "broken_authentication": (
        "authentication", "auth bypass", "login", "brute force", "credential", "session",
        "weak password", "xác thực", "mật khẩu yếu", "đăng nhập", "dò mật khẩu",
    ),
    "jwt": (
        "jwt", "json web token", "alg:none", "alg-none", "none algorithm", "hs256",
        "mã thông báo jwt",
    ),
    "oauth": (
        "oauth", "oauth2", "authorization code flow",
    ),
    "broken_access_control": (
        "idor", "insecure direct object", "object reference", "access control",
        "privilege escalation", "kiểm soát truy cập", "phân quyền", "leo thang đặc quyền",
    ),
    "ssrf": (
        "ssrf", "server-side request forgery", "gopher://", "169.254.169.254", "metadata",
        "giả mạo yêu cầu phía máy chủ",
    ),
    "http_host_header": (
        "host header", "host-header", "x-forwarded-host", "tiêu đề host",
    ),
    "http_request_smuggling": (
        "request smuggling", "http request smuggling", "buôn lậu yêu cầu",
    ),
    "web_cache_deception": (
        "cache deception", "web cache deception", "lừa đảo bộ nhớ đệm",
    ),
    "web_cache_poisoning": (
        "cache poisoning", "web cache poisoning", "đầu độc bộ nhớ đệm",
    ),
    "api_security": (
        "api security", "rest api", "bảo mật api",
    ),
    "graphql": (
        "graphql", "introspection", "__schema",
    ),
    "websockets": (
        "websocket", "websockets",
    ),
    "llm_attacks": (
        "prompt injection", "llm attack", "jailbreak", "tiêm prompt",
    ),
    "file_upload": (
        "file upload", "upload a", "multipart", "content-type bypass", "tải lên tệp",
    ),
    "race_condition": (
        "race condition", "toctou", "điều kiện tranh chấp",
    ),
    "information_disclosure": (
        "information disclosure", "stack trace", "verbose error", "leaked",
        "rò rỉ thông tin",
    ),
    "insecure_deserialization": (
        "deserialization", "insecure deserialization", "pickle", "ysoserial",
        "gadget chain", "giải tuần tự hóa không an toàn",
    ),
}


class TaxonomyNode(BaseModel):
    """One node in the shared vuln taxonomy — a parent category or a leaf technique."""

    id: str
    label: str
    parent_id: str | None = None
    kind: str  # "category" | "technique"
    catalog_ref: str = ""
    keywords: tuple[str, ...] = Field(default_factory=tuple)


class Taxonomy:
    """Parses ``vuln_search/catalog/INDEX.md`` into a category -> technique tree."""

    def __init__(self, index_path: str | Path | None = None) -> None:
        self.index_path = Path(index_path) if index_path else _default_index_path()
        self._nodes: list[TaxonomyNode] | None = None

    def _parse(self) -> list[TaxonomyNode]:
        if not self.index_path.is_file():
            return []
        nodes: list[TaxonomyNode] = []
        current_category: str | None = None
        for raw_line in self.index_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            heading = _HEADING_RE.match(line)
            if heading:
                label = heading.group(1).strip()
                current_category = _slugify(label)
                nodes.append(
                    TaxonomyNode(id=current_category, label=label, kind="category")
                )
                continue
            link = _LINK_RE.search(line)
            if link and current_category:
                label, href = link.group(1), link.group(2)
                slug = href.split("/")[0]
                nodes.append(
                    TaxonomyNode(
                        id=slug,
                        label=label,
                        parent_id=current_category,
                        kind="technique",
                        catalog_ref=href,
                        keywords=TECHNIQUE_KEYWORDS.get(slug, ()),
                    )
                )
        return nodes

    def nodes(self) -> list[TaxonomyNode]:
        if self._nodes is None:
            self._nodes = self._parse()
        return self._nodes

    def technique_nodes(self) -> list[TaxonomyNode]:
        return [n for n in self.nodes() if n.kind == "technique"]

    def category_nodes(self) -> list[TaxonomyNode]:
        return [n for n in self.nodes() if n.kind == "category"]

    def get(self, node_id: str) -> TaxonomyNode | None:
        return next((n for n in self.nodes() if n.id == node_id), None)

    def match_text(self, text: str) -> list[TaxonomyNode]:
        """Technique nodes whose keywords appear in ``text``, ranked by hit count desc."""
        low = normalize_text(text)
        scored = [
            (sum(1 for kw in n.keywords if normalize_text(kw) in low), n)
            for n in self.technique_nodes()
        ]
        scored = [(hits, n) for hits, n in scored if hits > 0]
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [n for _, n in scored]

    def tree(self) -> list[dict[str, object]]:
        """Nested category -> technique structure, for the notebook tree UI."""
        out: list[dict[str, object]] = []
        for cat in self.category_nodes():
            children = [n for n in self.nodes() if n.parent_id == cat.id]
            out.append(
                {
                    "id": cat.id,
                    "label": cat.label,
                    "children": [
                        {"id": t.id, "label": t.label, "catalog_ref": t.catalog_ref}
                        for t in children
                    ],
                }
            )
        return out
