"""Step 2: tool registry, http_get against a mock, and the safety gate."""

from ai_framework.agent.contracts import ToolCall
from ai_framework.tools.base import ToolContext, ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(HttpGetTool())
    reg.register(NoteFindingTool())
    return reg


def test_registry_serializes_schemas():
    schemas = {s["name"]: s for s in _registry().schemas()}
    assert "http_get" in schemas and "note_finding" in schemas
    assert schemas["http_get"]["input_schema"]["required"] == ["url"]


def test_http_get_returns_log(mock_server):
    reg = _registry()
    ctx = ToolContext(authorized_targets=set())  # localhost is always allowed
    result = reg.execute(ToolCall(id="c1", name="http_get", arguments={"url": mock_server}), ctx)
    assert result.ok
    assert "HTTP 200" in result.log and "mock target" in result.log


def test_unauthorized_target_refused():
    reg = _registry()
    ctx = ToolContext(authorized_targets=set())
    result = reg.execute(
        ToolCall(id="c1", name="http_get", arguments={"url": "http://evil.example.com"}), ctx
    )
    assert not result.ok
    assert "not authorized" in result.log


def test_authorized_target_passes_gate(monkeypatch):
    # An explicitly authorized non-local host must get past the safety gate. We stub the
    # network call so the test proves authorization, not connectivity.
    import ai_framework.tools.builtin as builtin

    class _Resp:
        status = 200

        def read(self, _n):
            return b"ok"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(builtin, "urlopen", lambda *a, **k: _Resp())
    tool = HttpGetTool()
    log = tool.run({"url": "http://203.0.113.1/"}, ToolContext(authorized_targets={"203.0.113.1"}))
    assert "HTTP 200" in log


def test_note_finding_is_pure():
    reg = _registry()
    ctx = ToolContext()
    result = reg.execute(
        ToolCall(id="c1", name="note_finding", arguments={"title": "X", "detail": "Y"}), ctx
    )
    assert result.ok and "FINDING: X" in result.log
