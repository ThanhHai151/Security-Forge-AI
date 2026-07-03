"""Deterministic ingestion of an external agent's raw output — no AI-provider call involved."""

from ai_framework.notebook.contracts import NodeStatus
from ai_framework.notebook.raw_log import RawLogStore
from ai_framework.notebook.store import NotebookStore
from ai_framework.supervisor.ingest import ingest_output
from ai_framework.taxonomy.tree import Taxonomy


def _stores(tmp_path):
    taxonomy = Taxonomy()
    notebooks = NotebookStore(tmp_path / "notebooks", taxonomy=taxonomy)
    raw_log = RawLogStore(tmp_path / "raw.jsonl")
    return notebooks, taxonomy, raw_log


def test_confirmed_marker_promotes_the_matched_technique(tmp_path):
    notebooks, taxonomy, raw_log = _stores(tmp_path)
    text = "CONFIRMED: sql injection - union-based, dumped users table"
    result = ingest_output("example.test.com", text, notebooks, taxonomy, raw_log)
    assert result.promoted == ["sql_injection"]
    node = notebooks.load("example.test.com").nodes["sql_injection"]
    assert node.status == NodeStatus.unconfirmed  # ingest never sets confirmed
    assert "union-based" in node.note


def test_new_finding_type_marker_files_a_custom_node_with_justification(tmp_path):
    notebooks, taxonomy, raw_log = _stores(tmp_path)
    text = "NEW_FINDING_TYPE: Business logic race - JUSTIFICATION: duplicate coupon redemption"
    result = ingest_output("example.test.com", text, notebooks, taxonomy, raw_log)
    assert result.custom_added == [
        {"label": "Business logic race", "justification": "duplicate coupon redemption"}
    ]
    custom = [n for n in notebooks.load("example.test.com").nodes.values() if n.is_custom]
    assert len(custom) == 1
    assert custom[0].justification == "duplicate coupon redemption"


def test_a_custom_node_is_never_created_without_an_explicit_marker(tmp_path):
    notebooks, taxonomy, raw_log = _stores(tmp_path)
    notebooks.get_or_create("example.test.com")  # matches real usage: notebook already exists
    # Free-form prose describing something novel, but no NEW_FINDING_TYPE marker used.
    text = "I noticed a weird business-logic quirk around coupon redemption but I'm not sure."
    result = ingest_output("example.test.com", text, notebooks, taxonomy, raw_log)
    assert result.custom_added == []
    assert not any(n.is_custom for n in notebooks.load("example.test.com").nodes.values())


def test_no_markers_falls_back_to_keyword_match(tmp_path):
    notebooks, taxonomy, raw_log = _stores(tmp_path)
    text = (
        "Poked around the login form and it looks vulnerable to sql injection via the "
        "username field."
    )
    result = ingest_output("example.test.com", text, notebooks, taxonomy, raw_log)
    assert result.promoted == ["sql_injection"]
    node = notebooks.load("example.test.com").nodes["sql_injection"]
    assert node.status == NodeStatus.unconfirmed


def test_raw_text_is_always_persisted_verbatim_regardless_of_outcome(tmp_path):
    notebooks, taxonomy, raw_log = _stores(tmp_path)
    text = "nothing recognizable in here at all"
    ingest_output("example.test.com", text, notebooks, taxonomy, raw_log)
    entries = raw_log.for_domain("example.test.com")
    assert len(entries) == 1
    assert entries[0].text == text


def test_ingest_never_promotes_an_already_confirmed_node_back_down(tmp_path):
    notebooks, taxonomy, raw_log = _stores(tmp_path)
    notebooks.set_status("example.test.com", "sql_injection", NodeStatus.confirmed)
    ingest_output(
        "example.test.com",
        "CONFIRMED: sql injection - re-tested",
        notebooks,
        taxonomy,
        raw_log,
    )
    node = notebooks.load("example.test.com").nodes["sql_injection"]
    assert node.status == NodeStatus.confirmed  # untouched, never downgraded/edited by ingest
