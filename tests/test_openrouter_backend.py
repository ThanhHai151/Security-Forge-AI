"""OpenRouterBackend: maps Hermes turns onto OpenRouter's OpenAI-compatible chat API."""

import json

import pytest

from ai_framework.agent.contracts import RunConfig, ToolCall, ToolResult, Turn
from ai_framework.agent.loop import run_loop
from ai_framework.models.openrouter_backend import OpenRouterBackend
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool


def _config():
    return RunConfig(goal="recon", target="http://t")


def _tools():
    return [{"name": "http_get", "description": "fetch",
             "input_schema": {"type": "object", "properties": {}}}]


def _backend(response, captured=None):
    def fake_post(url, payload, headers):
        if captured is not None:
            captured.update(url=url, payload=payload, headers=headers)
        return response

    return OpenRouterBackend(api_key="sk-test", http_post=fake_post)


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        OpenRouterBackend()


def test_act_parses_tool_calls_and_sends_openai_shape():
    response = {"choices": [{"message": {
        "content": "recon first",
        "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "http_get",
                                     "arguments": json.dumps({"url": "http://t"})}}],
    }}]}
    captured = {}
    action = _backend(response, captured).act("sys", [], _config(), _tools())

    assert action.done is False
    assert action.reasoning == "recon first"
    assert [tc.name for tc in action.tool_calls] == ["http_get"]
    assert action.tool_calls[0].arguments == {"url": "http://t"}

    assert captured["url"].endswith("/chat/completions")
    assert captured["headers"]["Authorization"] == "Bearer sk-test"
    assert captured["payload"]["tools"][0]["type"] == "function"
    roles = [m["role"] for m in captured["payload"]["messages"]]
    assert roles[0] == "system"
    assert "user" in roles  # first turn seeds a "Begin." user message


def test_act_without_tool_calls_is_done():
    response = {"choices": [{"message": {"content": "all done", "tool_calls": []}}]}
    action = _backend(response).act("sys", [], _config(), _tools())
    assert action.done is True
    assert action.tool_calls == []


def test_messages_include_prior_tool_results():
    turn = Turn(
        index=0, reasoning="r",
        tool_calls=[ToolCall(id="c1", name="http_get", arguments={"url": "http://t"})],
        tool_results=[ToolResult(call_id="c1", log="200 OK")],
    )
    captured = {}
    _backend({"choices": [{"message": {"content": "n", "tool_calls": []}}]}, captured).act(
        "sys", [turn], _config(), _tools()
    )
    messages = captured["payload"]["messages"]
    assert any(m["role"] == "assistant" and m.get("tool_calls") for m in messages)
    tool_msgs = [m for m in messages if m["role"] == "tool"]
    # Tool output is fenced as untrusted data before it reaches the provider (taint boundary).
    assert tool_msgs[0]["role"] == "tool"
    assert tool_msgs[0]["tool_call_id"] == "c1"
    assert "200 OK" in tool_msgs[0]["content"]
    assert "UNTRUSTED_OBSERVED_DATA" in tool_msgs[0]["content"]


def test_plan_returns_content():
    plan = _backend({"choices": [{"message": {"content": "do recon next"}}]}).plan(
        "sys", [], _config()
    )
    assert plan == "do recon next"


def test_openrouter_backend_drives_the_hermes_loop(mock_server):
    """Proof it plugs into the rotation exactly like the offline backend does."""
    reg = ToolRegistry()
    reg.register(HttpGetTool())
    reg.register(NoteFindingTool())

    scripted = iter([
        {"name": "http_get", "args": {"url": mock_server}},
        {"name": "note_finding", "args": {"title": "t", "detail": "d"}},
        None,  # done
    ])

    def fake_post(url, payload, headers):
        if "tools" not in payload:  # this is a plan() call
            return {"choices": [{"message": {"content": "next"}}]}
        step = next(scripted)
        if step is None:
            return {"choices": [{"message": {"content": "done", "tool_calls": []}}]}
        return {"choices": [{"message": {
            "content": "act",
            "tool_calls": [{"id": "c", "type": "function",
                            "function": {"name": step["name"],
                                         "arguments": json.dumps(step["args"])}}],
        }}]}

    backend = OpenRouterBackend(api_key="sk-test", http_post=fake_post)
    config = RunConfig(goal="recon", target=mock_server, authorized_targets={mock_server})
    run = run_loop(config, backend, reg)

    assert run.outcome == "done"
    assert len(run.transcript) == 2
    assert run.transcript[0].tool_calls[0].name == "http_get"
