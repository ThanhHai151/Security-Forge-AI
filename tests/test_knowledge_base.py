"""Knowledge Base: index, safe render, and search."""

from __future__ import annotations

from knowledge_base.index import KnowledgeBase, default_kb, parse_markdown
from knowledge_base.render import render_inline, render_markdown
from knowledge_base.search import search, search_errors


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ── indexing ──
def test_index_walks_and_records_entries(tmp_path):
    _write(tmp_path, "sql/README.md", "# SQL Injection\n\n> Bad query.\n\n## How it works\nstuff\n")
    _write(tmp_path, "xss/README.md", "# XSS\n\n## Detect\n")
    _write(tmp_path, "node_modules/pkg/README.md", "# junk\n")  # must be skipped

    kb = KnowledgeBase(tmp_path).index()
    assert len(kb) == 2
    entry = kb.get("sql")
    assert entry is not None
    assert entry.title == "SQL Injection"
    assert entry.summary == "Bad query."
    assert "How it works" in entry.headings
    assert entry.category == "sql"


def test_locale_variants_share_a_doc_id(tmp_path):
    _write(tmp_path, "sqli/README.md", "# SQL Injection\n")
    _write(tmp_path, "sqli/README.vi.md", "# Tiêm SQL\n")
    kb = KnowledgeBase(tmp_path).index()
    assert len(kb) == 1  # one document, two languages
    assert kb.get("sqli", "vi").title == "Tiêm SQL"
    assert kb.get("sqli", "en").title == "SQL Injection"
    # Missing locale falls back to English (i18n rule).
    assert kb.get("sqli", "fr").title == "SQL Injection"


def test_troubleshooting_flag_from_path(tmp_path):
    _write(tmp_path, "Troubleshooting_Guide/timeout.md", "# Timeout\n\nconnection refused\n")
    _write(tmp_path, "sql/README.md", "# SQL\n")
    kb = KnowledgeBase(tmp_path).index()
    assert kb.get("Troubleshooting_Guide/timeout").is_troubleshooting is True
    assert kb.get("sql").is_troubleshooting is False


def test_parse_markdown_ignores_headings_in_code():
    title, summary, headings = parse_markdown(
        "# Title\n\n> a summary\n\n```\n# not a heading\n```\n\n## Real Heading\n"
    )
    assert title == "Title"
    assert summary == "a summary"
    assert headings == ["Real Heading"]


# ── safe rendering (security-critical) ──
def test_render_escapes_payloads():
    html, _ = render_markdown("Try `<script>alert(1)</script>` here.")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_render_escapes_fenced_code():
    html, _ = render_markdown("```html\n<img src=x onerror=alert(1)>\n```")
    assert "<img" not in html
    assert "&lt;img" in html
    assert 'class="language-html"' in html


def test_render_drops_javascript_links():
    html = render_inline("[click](javascript:alert(1))")
    assert "javascript:" not in html
    assert "click" in html
    assert "<a" not in html  # unsafe target dropped, visible text kept


def test_render_keeps_safe_links_and_emphasis():
    html = render_inline("see [docs](https://example.com) and **bold** and *italic*")
    assert '<a href="https://example.com">docs</a>' in html
    assert "<strong>bold</strong>" in html
    assert "<em>italic</em>" in html


def test_render_headings_get_anchor_ids_and_toc():
    html, toc = render_markdown("# Top\n\n## How it works\n\n## How it works\n")
    assert 'id="how-it-works"' in html
    assert 'id="how-it-works-2"' in html  # de-duplicated
    assert [t["text"] for t in toc] == ["Top", "How it works", "How it works"]


def test_render_table_and_list():
    html, _ = render_markdown("| a | b |\n|---|---|\n| 1 | 2 |\n")
    assert "<table>" in html and "<th>a</th>" in html and "<td>1</td>" in html
    html2, _ = render_markdown("- one\n- two\n")
    assert html2.count("<li>") == 2 and "<ul>" in html2


# ── search ──
def test_full_text_search_ranks_title_matches_first(tmp_path):
    _write(tmp_path, "sqli/README.md", "# SQL Injection\n\n> Untrusted input alters a SQL query.\n")
    _write(tmp_path, "xss/README.md", "# XSS\n\nSometimes paired with sql elsewhere.\n")
    kb = KnowledgeBase(tmp_path).index()
    hits = search(kb, "sql injection")
    assert hits[0].id == "sqli"
    assert hits[0].score > 0


def test_search_no_terms_returns_empty(tmp_path):
    kb = KnowledgeBase(tmp_path).index()
    assert search(kb, "   ") == []


def test_error_search_restricts_to_troubleshooting(tmp_path):
    _write(tmp_path, "errors/db.md", "# DB errors\n\nconnection refused timeout\n")
    _write(tmp_path, "sql/README.md", "# SQL\n\nconnection pooling notes\n")
    kb = KnowledgeBase(tmp_path).index()
    hits = search_errors(kb, "connection refused")
    assert hits and all(h.id == "errors/db" for h in hits)


# ── the bundled catalog actually indexes ──
def test_default_kb_indexes_the_catalog():
    kb = default_kb()
    assert len(kb) >= 20
    sqli = kb.get("sql_injection")
    assert sqli is not None and "SQL" in sqli.title
    assert search(kb, "parameterized queries")
