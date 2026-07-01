"""Guardrails: block dead-end calls and halt runs that stop making progress."""

from ai_framework.agent.contracts import ToolCall
from ai_framework.agent.guardrails import GuardrailConfig, GuardrailController
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool
from ai_framework.tools.security import HttpRequestTool


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(HttpGetTool())       # idempotent
    reg.register(HttpRequestTool())   # mutating
    return reg


def test_identical_failing_call_is_blocked():
    ctrl = GuardrailController(GuardrailConfig(exact_failure_block_after=3))
    reg = _registry()
    call = ToolCall(id="c", name="http_get", arguments={"url": "http://x/"})
    for _ in range(3):
        assert ctrl.check(call, reg).allow  # allowed while under threshold
        ctrl.record(call, ok=False)
    assert not ctrl.check(call, reg).allow  # blocked on the 4th attempt


def test_mutating_tool_has_a_tighter_leash():
    ctrl = GuardrailController(
        GuardrailConfig(mutating_failure_block_after=2, same_tool_halt_after=6)
    )
    reg = _registry()
    # Two DISTINCT mutating calls fail; the exact-call counter never trips, but the
    # per-tool mutating leash (2) does.
    for i in range(2):
        c = ToolCall(id=f"c{i}", name="http_request", arguments={"url": f"http://x/{i}"})
        assert ctrl.check(c, reg).allow
        ctrl.record(c, ok=False)
    blocked = ToolCall(id="c9", name="http_request", arguments={"url": "http://x/new"})
    assert not ctrl.check(blocked, reg).allow


def test_no_progress_halts_the_run():
    ctrl = GuardrailController(GuardrailConfig(no_progress_halt_after=3))
    for _ in range(2):
        ctrl.observe_turn(any_ok=False)
        assert not ctrl.should_halt()
    ctrl.observe_turn(any_ok=False)
    assert ctrl.should_halt()
    assert "no successful action" in ctrl.halt_reason


def test_success_resets_progress_and_tool_failures():
    ctrl = GuardrailController(GuardrailConfig(no_progress_halt_after=2, same_tool_halt_after=2))
    reg = _registry()
    ctrl.observe_turn(any_ok=False)
    ctrl.observe_turn(any_ok=True)  # progress resets the counter
    ctrl.observe_turn(any_ok=False)
    assert not ctrl.should_halt()

    call = ToolCall(id="c", name="http_get", arguments={"url": "http://x/"})
    ctrl.record(call, ok=False)
    ctrl.record(call, ok=True)  # a success clears the consecutive-failure tally
    ctrl.record(call, ok=False)
    assert ctrl.check(call, reg).allow
