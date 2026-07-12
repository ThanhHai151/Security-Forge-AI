"""Quantitative RoE controls are enforced by the runtime."""

from datetime import UTC, datetime, timedelta

import pytest

from ai_framework.agent.contracts import ToolCall
from ai_framework.harness.contracts import RulesOfEngagement
from ai_framework.harness.limits import EngagementLimiter
from ai_framework.tools.auth import LoginTool
from ai_framework.tools.security import HttpRequestTool


def _roe(**changes) -> RulesOfEngagement:
    now = datetime.now(UTC)
    values = {
        "authorization_confirmed": True,
        "authorization_reference": "SOW-1",
        "authorized_targets": ["example.test"],
        "window_start": now - timedelta(minutes=1),
        "window_end": now + timedelta(minutes=1),
        "max_requests_per_second": 100,
    }
    values.update(changes)
    return RulesOfEngagement(**values)


def test_request_body_limit_fails_before_network_execution():
    limiter = EngagementLimiter(_roe(max_request_body_bytes=4))
    call = ToolCall(
        id="c1",
        name="http_request",
        arguments={"url": "https://example.test", "body": "12345"},
    )
    with pytest.raises(PermissionError, match="RoE limit"):
        limiter.before(call, HttpRequestTool())


def test_authentication_attempt_limit_is_per_account():
    limiter = EngagementLimiter(_roe(max_auth_attempts_per_account=1))
    call = ToolCall(
        id="c1",
        name="login",
        arguments={
            "url": "https://example.test/login",
            "data": {"username": "alice", "password": "secret"},
        },
    )
    acquired = limiter.before(call, LoginTool())
    limiter.after(acquired)
    with pytest.raises(PermissionError, match="authentication-attempt limit"):
        limiter.before(call, LoginTool())
