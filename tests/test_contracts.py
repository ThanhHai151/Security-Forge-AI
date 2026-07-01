"""Step 1: data contracts round-trip through JSON and validate inputs."""

import pytest
from pydantic import ValidationError

from ai_framework.agent.contracts import (
    MemoryKind,
    MemoryRecord,
    Run,
    RunConfig,
    ToolCall,
    ToolResult,
    Turn,
)


def test_turn_round_trip():
    turn = Turn(
        index=0,
        reasoning="no recon yet",
        tool_calls=[ToolCall(id="c1", name="http_get", arguments={"url": "http://x"})],
        tool_results=[ToolResult(call_id="c1", log="200 OK", ok=True)],
        next_plan="inspect response",
    )
    restored = Turn.model_validate_json(turn.model_dump_json())
    assert restored == turn


def test_memory_record_round_trip():
    rec = MemoryRecord(
        id="m1", kind=MemoryKind.attempt, target="x", technique="sqli", body="failed"
    )
    restored = MemoryRecord.model_validate_json(rec.model_dump_json())
    assert restored == rec
    assert restored.created_at.tzinfo is not None


def test_run_round_trip():
    run = Run(config=RunConfig(goal="g", target="t"), transcript=[Turn(index=0)])
    assert Run.model_validate_json(run.model_dump_json()) == run


def test_invalid_tool_arguments_rejected():
    with pytest.raises(ValidationError):
        ToolCall(id="c1", name="http_get", arguments="not-a-dict")  # type: ignore[arg-type]


def test_invalid_memory_kind_rejected():
    with pytest.raises(ValidationError):
        MemoryRecord(id="m1", kind="bogus", body="x")  # type: ignore[arg-type]
