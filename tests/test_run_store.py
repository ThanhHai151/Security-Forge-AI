"""Durable run storage: checkpoint, reload, and list persisted runs."""

from ai_framework.agent.contracts import Run, RunConfig, ToolCall, ToolResult, Turn
from ai_framework.agent.run_store import JsonRunStore


def _run() -> Run:
    run = Run(config=RunConfig(goal="g", target="http://t"))
    run.transcript.append(
        Turn(
            index=0,
            reasoning="r",
            tool_calls=[ToolCall(id="c0", name="http_get", arguments={"url": "http://t"})],
            tool_results=[ToolResult(call_id="c0", log="HTTP 200")],
        )
    )
    run.outcome = "done"
    return run


def test_save_and_load_roundtrip(tmp_path):
    store = JsonRunStore(tmp_path)
    run = _run()
    store.save(run)
    loaded = store.load(run.id)
    assert loaded == run  # exact round-trip, id preserved


def test_load_unknown_returns_none(tmp_path):
    assert JsonRunStore(tmp_path).load("nope") is None


def test_list_runs_summaries(tmp_path):
    store = JsonRunStore(tmp_path)
    run = _run()
    store.save(run)
    listing = store.list_runs()
    assert len(listing) == 1
    assert listing[0]["id"] == run.id
    assert listing[0]["outcome"] == "done"
    assert listing[0]["turns"] == 1
    assert listing[0]["target"] == "http://t"


def test_save_is_atomic_leaves_no_tmp(tmp_path):
    store = JsonRunStore(tmp_path)
    store.save(_run())
    assert not list(tmp_path.glob("*.tmp"))
