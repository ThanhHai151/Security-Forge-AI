"""The RoE harness is enforced by the autonomous tool boundary, not only by prompts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ai_framework.agent.contracts import ToolCall
from ai_framework.harness.contracts import RulesOfEngagement
from ai_framework.harness.runtime import ToolPolicyError, enforce_tool_policy
from ai_framework.tools.base import ToolContext, ToolRegistry
from ai_framework.tools.builtin import HttpGetTool
from ai_framework.tools.security import HttpRequestTool
from ai_framework.tools.session import ScopedRedirectHandler


def _roe(**overrides) -> RulesOfEngagement:
    now = datetime.now(UTC)
    values = {
        "engagement_id": "ENG-42",
        "authorization_confirmed": True,
        "authorization_reference": "SOW-42",
        "authorized_targets": ["app.example.test"],
        "window_start": now - timedelta(minutes=5),
        "window_end": now + timedelta(minutes=5),
    }
    values.update(overrides)
    return RulesOfEngagement(**values)


class _Response:
    status = 200
    headers: dict[str, str] = {}

    def read(self, _size: int) -> bytes:
        return b"ok"

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Session:
    def open(self, _request, _timeout: float):
        return _Response()


def test_runtime_roe_rejects_off_scope_target_despite_legacy_allowlist():
    registry = ToolRegistry()
    registry.register(HttpGetTool())
    ctx = ToolContext(
        authorized_targets={"other.example.test"},
        primary_target="https://app.example.test",
        rules_of_engagement=_roe(),
    )
    result = registry.execute(
        ToolCall(id="get-1", name="http_get", arguments={"url": "https://other.example.test/"}),
        ctx,
    )
    assert not result.ok
    assert "outside scope" in result.log


def test_runtime_roe_binds_operator_approval_to_the_exact_tool_call():
    tool = HttpRequestTool()
    registry = ToolRegistry()
    registry.register(tool)
    call = ToolCall(
        id="probe-1",
        name="http_request",
        arguments={"url": "https://app.example.test/search?q=red", "headers": {"X-Test": "1"}},
    )
    ctx = ToolContext(
        primary_target="https://app.example.test",
        rules_of_engagement=_roe(),
        session=_Session(),
    )

    with pytest.raises(ToolPolicyError) as raised:
        enforce_tool_policy(call, tool, ctx)
    approval = raised.value.approval_token
    assert approval.startswith("roe-")

    ctx.approved_action_tokens.add(approval)
    result = registry.execute(call, ctx)
    assert result.ok
    assert "HTTP 200 GET" in result.log

    changed = ToolCall(
        id="probe-2",
        name="http_request",
        arguments={"url": "https://app.example.test/search?q=changed", "headers": {"X-Test": "1"}},
    )
    with pytest.raises(ToolPolicyError) as changed_error:
        enforce_tool_policy(changed, tool, ctx)
    assert changed_error.value.approval_token != approval


def test_redirect_handler_checks_each_redirect_hop_before_following():
    seen: list[str] = []
    handler = ScopedRedirectHandler(lambda url: seen.append(url) or (_ for _ in ()).throw(
        PermissionError("off-scope redirect")
    ))

    with pytest.raises(PermissionError, match="off-scope redirect"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://outside.example.test/")
    assert seen == ["https://outside.example.test/"]
