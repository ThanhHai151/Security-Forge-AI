"""The shared vulnerability taxonomy: parses vuln_search/catalog/INDEX.md into a tree."""

from ai_framework.taxonomy.tree import Taxonomy


def test_parses_six_categories_and_all_catalog_entries():
    taxonomy = Taxonomy()
    cats = taxonomy.category_nodes()
    assert {c.id for c in cats} == {
        "injection",
        "client-side",
        "authentication-identity",
        "server-side-infrastructure",
        "apis-modern",
        "other",
    }
    techniques = taxonomy.technique_nodes()
    assert len(techniques) == 29
    cat_ids = {c.id for c in cats}
    assert all(t.parent_id in cat_ids for t in techniques)


def test_tree_nests_categories_and_techniques():
    tree = Taxonomy().tree()
    injection = next(c for c in tree if c["id"] == "injection")
    assert {t["id"] for t in injection["children"]} >= {"sql_injection", "nosql_injection"}


def test_match_text_resolves_english_and_vietnamese_sql_injection():
    taxonomy = Taxonomy()
    en = taxonomy.match_text("please test for sql injection on the login form")
    vi = taxonomy.match_text("kiểm tra lỗi sql injection của hệ thống này")
    assert en and en[0].id == "sql_injection"
    assert vi and vi[0].id == "sql_injection"


def test_match_text_no_match_returns_empty():
    assert Taxonomy().match_text("just saying hello") == []


def test_missing_index_file_returns_no_nodes(tmp_path):
    taxonomy = Taxonomy(index_path=tmp_path / "missing.md")
    assert taxonomy.nodes() == []
