"""The Hermes notebook: a per-domain confirmed/unconfirmed/untested vuln tree."""

from ai_framework.notebook.contracts import NodeStatus
from ai_framework.notebook.store import NotebookStore
from ai_framework.taxonomy.tree import Taxonomy


def _store(tmp_path) -> NotebookStore:
    return NotebookStore(tmp_path / "notebooks", taxonomy=Taxonomy())


def test_get_or_create_seeds_every_technique_untested(tmp_path):
    store = _store(tmp_path)
    notebook = store.get_or_create("example.test.com")
    assert len(notebook.nodes) == 29
    assert all(n.status == NodeStatus.untested for n in notebook.nodes.values())


def test_new_domain_never_carries_over_another_domains_status(tmp_path):
    store = _store(tmp_path)
    store.set_status("a.test.com", "sql_injection", NodeStatus.confirmed)
    fresh = store.get_or_create("b.test.com")
    assert fresh.nodes["sql_injection"].status == NodeStatus.untested


def test_set_status_confirmed_is_a_human_action(tmp_path):
    store = _store(tmp_path)
    notebook = store.set_status(
        "example.test.com",
        "sql_injection",
        NodeStatus.confirmed,
        note="confirmed via sqlmap",
        updated_by="user",
    )
    node = notebook.nodes["sql_injection"]
    assert node.status == NodeStatus.confirmed
    assert node.updated_by == "user"
    assert node.note == "confirmed via sqlmap"


def test_ingest_promote_never_sets_confirmed(tmp_path):
    store = _store(tmp_path)
    notebook = store.ingest_promote("example.test.com", "xss", note="reflected param seen")
    assert notebook.nodes["xss"].status == NodeStatus.unconfirmed
    assert notebook.nodes["xss"].updated_by == "ingest"


def test_ingest_promote_never_downgrades_an_existing_status(tmp_path):
    store = _store(tmp_path)
    store.set_status("example.test.com", "xss", NodeStatus.confirmed, updated_by="user")
    notebook = store.ingest_promote("example.test.com", "xss")
    assert notebook.nodes["xss"].status == NodeStatus.confirmed  # untouched, not downgraded


def test_link_finding_appends_id(tmp_path):
    store = _store(tmp_path)
    store.set_status("example.test.com", "sql_injection", NodeStatus.confirmed)
    notebook = store.link_finding("example.test.com", "sql_injection", "f-123")
    assert "f-123" in notebook.nodes["sql_injection"].finding_ids


def test_tree_view_merges_status_onto_taxonomy(tmp_path):
    store = _store(tmp_path)
    store.set_status("example.test.com", "sql_injection", NodeStatus.confirmed)
    tree = store.tree_view("example.test.com")
    injection = next(c for c in tree if c["id"] == "injection")
    sqli = next(t for t in injection["children"] if t["id"] == "sql_injection")
    assert sqli["status"] == "confirmed"


def test_list_domains_summarizes_confirmed_counts(tmp_path):
    store = _store(tmp_path)
    store.set_status("example.test.com", "sql_injection", NodeStatus.confirmed)
    domains = store.list_domains()
    assert any(d["domain"] == "example.test.com" and d["confirmed"] == 1 for d in domains)


# ── v2: in_progress, custom nodes, hierarchy, folders, chains ──


def test_set_in_progress_is_exclusive_and_cleared_by_status_change(tmp_path):
    store = _store(tmp_path)
    store.set_in_progress("example.test.com", "sql_injection")
    store.set_in_progress("example.test.com", "xss")
    notebook = store.load("example.test.com")
    assert notebook.nodes["xss"].in_progress is True
    assert notebook.nodes["sql_injection"].in_progress is False

    store.set_status("example.test.com", "xss", NodeStatus.unconfirmed)
    notebook = store.load("example.test.com")
    assert notebook.nodes["xss"].in_progress is False


def test_add_custom_node_appears_only_under_synthesized_others_category(tmp_path):
    store = _store(tmp_path)
    store.add_custom_node("example.test.com", "Business logic race", "duplicate coupon redemption")
    tree = store.tree_view("example.test.com")
    others = next((c for c in tree if c["id"] == "others"), None)
    assert others is not None
    assert others["children"][0]["label"] == "Business logic race"
    assert others["children"][0]["justification"] == "duplicate coupon redemption"
    # not duplicated into any real taxonomy category
    assert not any(
        any(child["id"].startswith("custom:") for child in c["children"])
        for c in tree
        if c["id"] != "others"
    )


def test_add_child_nests_under_parent_in_roots_and_children(tmp_path):
    store = _store(tmp_path)
    store.get_or_create("root.test.com")
    store.add_child("root.test.com", "api.root.test.com")
    roots = store.roots_and_children()
    root = next(r for r in roots if r["domain"] == "root.test.com")
    assert [c["domain"] for c in root["children"]] == ["api.root.test.com"]
    # the child itself never appears as a top-level root
    assert all(r["domain"] != "api.root.test.com" for r in roots)


def test_child_gets_its_own_independent_notebook(tmp_path):
    store = _store(tmp_path)
    store.add_child("root.test.com", "api.root.test.com")
    store.set_status("root.test.com", "sql_injection", NodeStatus.confirmed)
    child = store.load("api.root.test.com")
    assert child.nodes["sql_injection"].status == NodeStatus.untested
    assert child.parent_domain == "root.test.com"


def test_add_chain_records_exploit_chain_link(tmp_path):
    store = _store(tmp_path)
    notebook = store.add_chain(
        "example.test.com", "sql_injection", "broken_access_control", "pivot"
    )
    assert notebook.chains[0].from_node == "sql_injection"
    assert notebook.chains[0].to_node == "broken_access_control"
    assert notebook.chains[0].note == "pivot"
