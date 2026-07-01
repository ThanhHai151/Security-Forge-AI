"""Step 4: the Hermes loop runs end to end on the offline backend."""

from ai_framework.agent.contracts import Run, RunConfig
from ai_framework.agent.loop import run_loop
from ai_framework.models.offline import OfflineBackend
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool


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


def test_run_replays_from_json(mock_server):
    config = RunConfig(goal="recon", target=mock_server, authorized_targets={mock_server})
    run = run_loop(config, OfflineBackend(), _registry())
    assert Run.model_validate_json(run.model_dump_json()) == run
