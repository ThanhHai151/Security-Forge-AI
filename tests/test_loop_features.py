"""Loop integration: plan feed-forward, findings capture, guardrail halt, OPSEC pacing."""

from typing import Any

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn
from ai_framework.agent.guardrails import GuardrailConfig, GuardrailController
from ai_framework.agent.loop import run_loop
from ai_framework.agent.opsec import Pacer
from ai_framework.agent.system import with_plan
from ai_framework.models.base import ActResponse
from ai_framework.models.offline import OfflineBackend
from ai_framework.notes.store import JsonlFindingStore
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(HttpGetTool())
    reg.register(NoteFindingTool())
    return reg


def test_with_plan_injects_and_noops_when_empty():
    assert with_plan("SYS", "") == "SYS"
    out = with_plan("SYS", "do X next")
    assert "do X next" in out and out.startswith("SYS")


class _RecordingBackend:
    """Captures the system prompt it is handed each turn, and emits a marked plan."""

    name = "recording"

    def __init__(self) -> None:
        self.systems: list[str] = []

    def act(
        self,
        system: str,
        transcript: list[Turn],
        config: RunConfig,
        tools: list[dict[str, Any]],
    ) -> ActResponse:
        self.systems.append(system)
        if not transcript:
            return ActResponse(
                reasoning="recon",
                tool_calls=[ToolCall(id="c0", name="http_get", arguments={"url": config.target})],
            )
        return ActResponse(done=True)

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        return "PLAN_MARKER_42 pursue the next lead"


def test_plan_feeds_forward_into_next_action(mock_server):
    backend = _RecordingBackend()
    config = RunConfig(goal="g", target=mock_server, authorized_targets={mock_server})
    run_loop(config, backend, _registry())
    # First act() had no prior plan; the second must carry the plan produced from turn 0's logs.
    assert "PLAN_MARKER_42" not in backend.systems[0]
    assert "PLAN_MARKER_42" in backend.systems[1]


def test_findings_are_captured_during_a_run(tmp_path, mock_server):
    findings = JsonlFindingStore(tmp_path / "f.jsonl")
    config = RunConfig(goal="recon", target=mock_server, authorized_targets={mock_server})
    run = run_loop(config, OfflineBackend(), _registry(), findings=findings)
    captured = findings.for_run(run.id)
    assert len(captured) == 1
    assert captured[0].target == mock_server
    assert captured[0].title


class _AlwaysFails:
    """Never signals done; keeps proposing a call that fails, to exercise the loop-breaker."""

    name = "fails"

    def act(self, system, transcript, config, tools):
        n = len(transcript)
        return ActResponse(
            reasoning="try",
            tool_calls=[ToolCall(id=f"c{n}", name="http_get", arguments={"url": "http://blocked/"})],
        )

    def plan(self, system, transcript, config):
        return "keep trying"


def test_guardrail_halts_a_stuck_run(mock_server):
    config = RunConfig(
        goal="g", target=mock_server, step_budget=50, authorized_targets={mock_server}
    )
    guardrail = GuardrailController(GuardrailConfig(no_progress_halt_after=3))
    run = run_loop(config, _AlwaysFails(), _registry(), guardrail=guardrail)
    assert run.outcome == "guardrail_halt"
    assert len(run.transcript) < 50  # halted well before the step budget
    assert "no successful action" in run.error


def test_opsec_pacer_runs_in_loop(mock_server):
    # Pacing must not change the outcome — just prove the wired pacer executes cleanly.
    config = RunConfig(goal="g", target=mock_server, authorized_targets={mock_server})
    pacer = Pacer(0.0, 0.0)  # disabled: instant
    run = run_loop(config, OfflineBackend(), _registry(), pacer=pacer)
    assert run.outcome == "done"
