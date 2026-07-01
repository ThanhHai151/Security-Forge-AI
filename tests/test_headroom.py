"""Tests for Headroom: token accounting, the fit() compaction ladder, and loop wiring."""

from __future__ import annotations

import pytest

from ai_framework.agent.contracts import (
    Budget,
    MemoryKind,
    MemoryRecord,
    RunConfig,
    ToolCall,
    ToolResult,
    Turn,
)
from ai_framework.agent.loop import run_loop
from ai_framework.headroom import (
    TurnRequest,
    estimate_tokens,
    fit,
    reset_token_counter,
    set_token_counter,
)
from ai_framework.headroom.budget import count_tokens, tiktoken_counter
from ai_framework.models.offline import OfflineBackend
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool


def _turn(i: int, log: str = "ok", reasoning: str = "thinking") -> Turn:
    return Turn(
        index=i,
        reasoning=reasoning,
        tool_calls=[ToolCall(id=f"t{i}", name="http_get", arguments={"url": "x"})],
        tool_results=[ToolResult(call_id=f"t{i}", log=log, ok=True)],
        next_plan=f"plan {i}",
    )


def test_estimate_tokens_monotonic() -> None:
    assert estimate_tokens("") == 0
    assert estimate_tokens("a") == 1
    assert estimate_tokens("a" * 40) == 10


def test_pluggable_token_counter_is_used_then_resets() -> None:
    # Install a word-count counter; everything in Headroom must route through it.
    set_token_counter(lambda text: len(text.split()))
    try:
        assert count_tokens("one two three") == 3
    finally:
        reset_token_counter()
    # After reset, the default heuristic is back.
    assert count_tokens("aaaa") == 1


def test_tiktoken_counter_when_available() -> None:
    tiktoken = pytest.importorskip("tiktoken")  # noqa: F841
    count = tiktoken_counter()
    assert count("") == 0
    assert count("hello world") >= 1


def test_budget_reserves_output_headroom() -> None:
    b = Budget.from_window(1000, reserved_fraction=0.25)
    assert b.reserved_output_headroom == 250
    assert b.input_budget == 750


def test_fit_passthrough_when_under_budget() -> None:
    req = TurnRequest(system="sys", transcript=[_turn(0)], tools=[], memory=[])
    fitted = fit(req, Budget(context_window=200_000))
    assert fitted.report.actions == []
    assert fitted.report.within_budget
    assert fitted.report.tokens_before == fitted.report.tokens_after
    assert len(fitted.transcript) == 1
    assert fitted.transcript[0].reasoning == "thinking"


def test_fit_compacts_and_keeps_recent_turns() -> None:
    transcript = [_turn(i, log="line\n" * 200, reasoning="long reasoning " * 20) for i in range(8)]
    memory = [
        MemoryRecord(id=f"m{i}", kind=MemoryKind.lesson, body="lesson " * 50) for i in range(5)
    ]
    req = TurnRequest(system="sys", transcript=transcript, tools=[], memory=memory)
    budget = Budget(
        context_window=400,
        reserved_output_headroom=100,
        keep_recent_turns=2,
        max_tool_log_tokens=10,
    )

    fitted = fit(req, budget)

    # It actually shrank the request and fit within the input budget.
    assert fitted.report.tokens_after < fitted.report.tokens_before
    assert fitted.report.tokens_after <= budget.input_budget
    assert fitted.report.within_budget
    assert fitted.report.actions  # ladder ran, recorded, no silent loss

    # The two most recent turns survive intact in the transcript.
    assert [t.index for t in fitted.transcript[-2:]] == [6, 7]
    # Older turns were summarized into the synopsis folded into the system prompt.
    assert "Prior context" in fitted.system
    assert "turn 0" in fitted.synopsis


def test_fit_ladder_order_drops_reasoning_first() -> None:
    # A budget tight enough to need dropping reasoning but not summarizing.
    transcript = [_turn(i, log="x", reasoning="r" * 400) for i in range(4)]
    req = TurnRequest(system="s", transcript=transcript, tools=[], memory=[])
    budget = Budget(context_window=400, reserved_output_headroom=0, keep_recent_turns=2)

    fitted = fit(req, budget)
    kinds = [a.kind for a in fitted.report.actions]
    assert "drop_reasoning" in kinds
    # Recent turns keep their reasoning; older ones were cleared.
    assert fitted.transcript[-1].reasoning == "r" * 400
    assert fitted.transcript[0].reasoning == ""


def test_run_loop_records_compaction_reports(tmp_path) -> None:
    registry = ToolRegistry()
    registry.register(HttpGetTool())
    registry.register(NoteFindingTool())
    config = RunConfig(
        goal="recon",
        target="http://localhost:8000",
        step_budget=5,
        authorized_targets={"http://localhost:8000"},
    )
    budget = Budget(context_window=100_000)

    run = run_loop(config, OfflineBackend(), registry, memory=None, budget=budget)

    assert run.compaction_reports  # one per model call
    assert all(r.within_budget for r in run.compaction_reports)
    # Loop still completed the offline run normally with Headroom in front of the backend.
    assert run.transcript
