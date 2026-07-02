"""Step 4: the Hermes loop runs end to end on the offline backend."""

import threading

from ai_framework.agent.contracts import Run, RunConfig, ToolCall
from ai_framework.agent.loop import run_loop
from ai_framework.models.base import ActResponse
from ai_framework.models.offline import OfflineBackend
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool
from ai_framework.tools.security import HttpRequestTool


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(HttpGetTool())
    reg.register(NoteFindingTool())
    return reg


def test_loop_runs_multi_turn(mock_server):
    config = RunConfig(goal="recon", target=mock_server, authorized_targets={mock_server})
    run = run_loop(config, OfflineBackend(), _registry())

    assert run.outcome == "done"
    assert len(run.transcript) >= 2
    for turn in run.transcript:
        assert turn.reasoning
        assert len(turn.tool_calls) >= 1
        assert len(turn.tool_results) == len(turn.tool_calls)
        assert turn.next_plan
    # First turn recon succeeded against the mock target.
    assert run.transcript[0].tool_results[0].ok


def test_loop_halts_at_step_budget(mock_server):
    # A backend that never says done must be bounded by the budget.
    class _NeverDone(OfflineBackend):
        def act(self, system, transcript, config, tools):
            action = super().act(system, transcript, config, tools)
            action.done = False
            return action

    config = RunConfig(
        goal="x", target=mock_server, step_budget=3, authorized_targets={mock_server}
    )
    run = run_loop(config, _NeverDone(), _registry())
    assert run.outcome == "step_budget_reached"
    assert len(run.transcript) == 3


def test_cancel_set_before_start_stops_with_no_turns(mock_server):
    """A Stop click that lands before the loop's first turn: no work done, outcome=stopped."""
    config = RunConfig(
        goal="x", target=mock_server, step_budget=5, authorized_targets={mock_server}
    )
    cancel = threading.Event()
    cancel.set()
    run = run_loop(config, OfflineBackend(), _registry(), cancel=cancel)
    assert run.outcome == "stopped"
    assert run.transcript == []


def test_cancel_set_mid_run_stops_before_the_next_turn(mock_server):
    """A Stop click mid-run: the in-flight turn finishes, no further turn starts."""

    class _CancelsAfterFirstAct(OfflineBackend):
        def __init__(self, cancel: threading.Event) -> None:
            super().__init__()
            self._cancel = cancel
            self.calls = 0

        def act(self, system, transcript, config, tools):
            self.calls += 1
            if self.calls == 1:
                self._cancel.set()  # operator hits Stop while turn 1 is in flight
            action = super().act(system, transcript, config, tools)
            action.done = False  # would otherwise finish on its own; force reliance on cancel
            return action

    config = RunConfig(
        goal="x", target=mock_server, step_budget=5, authorized_targets={mock_server}
    )
    cancel = threading.Event()
    backend = _CancelsAfterFirstAct(cancel)
    run = run_loop(config, backend, _registry(), cancel=cancel)

    assert run.outcome == "stopped"
    assert len(run.transcript) == 1  # turn 1 completed; turn 2 never started
    assert backend.calls == 1


def test_run_replays_from_json(mock_server):
    config = RunConfig(goal="recon", target=mock_server, authorized_targets={mock_server})
    run = run_loop(config, OfflineBackend(), _registry())
    assert Run.model_validate_json(run.model_dump_json()) == run


def test_hold_mutating_defers_state_changing_calls(mock_server):
    """A mutating (state-changing) call is held for approval, never auto-executed."""

    class _EmitsMutating(OfflineBackend):
        def act(self, system, transcript, config, tools):
            if not transcript:
                return ActResponse(
                    reasoning="Try a POST.",
                    tool_calls=[
                        ToolCall(
                            id="m0",
                            name="http_request",
                            arguments={"url": f"{mock_server}/x", "method": "POST", "body": "z"},
                        )
                    ],
                )
            return ActResponse(reasoning="done", done=True)

    reg = _registry()
    reg.register(HttpRequestTool())
    held: list[ToolCall] = []
    config = RunConfig(
        goal="x", target=mock_server, step_budget=3, authorized_targets={mock_server}
    )
    run = run_loop(
        config,
        _EmitsMutating(),
        reg,
        hold_mutating=True,
        on_hold=lambda call, _reason: held.append(call),
    )

    # The call was captured for approval and its result marks it held, not executed.
    assert len(held) == 1 and held[0].name == "http_request"
    result = run.transcript[0].tool_results[0]
    assert result.ok is False
    assert "held for manual approval" in result.log
