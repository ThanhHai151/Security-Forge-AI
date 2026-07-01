"""Step 3: the offline backend emits valid, deterministic tool calls."""

from ai_framework.agent.contracts import RunConfig, ToolResult, Turn
from ai_framework.models.offline import OfflineBackend


def _config() -> RunConfig:
    return RunConfig(goal="recon", target="http://localhost:8000")


def test_first_action_is_http_get():
    action = OfflineBackend().act("sys", [], _config(), [])
    assert not action.done
    assert action.tool_calls[0].name == "http_get"
    assert action.tool_calls[0].arguments == {"url": "http://localhost:8000"}


def test_second_action_is_note_finding():
    recon = Turn(index=0, tool_calls=OfflineBackend().act("s", [], _config(), []).tool_calls,
                 tool_results=[ToolResult(call_id="t0-c0", log="HTTP 200")])
    action = OfflineBackend().act("sys", [recon], _config(), [])
    assert action.tool_calls[0].name == "note_finding"


def test_backend_is_deterministic():
    cfg = _config()
    a = OfflineBackend().act("sys", [], cfg, [])
    b = OfflineBackend().act("sys", [], cfg, [])
    assert a == b
