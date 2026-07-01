"""Security tool catalog: decode/encode (local), recon over a mock, and the auth gate."""

from ai_framework.agent.contracts import ToolCall
from ai_framework.tools.base import ToolContext, ToolRegistry
from ai_framework.tools.security import (
    DecodeEncodeTool,
    HttpRequestTool,
    InspectHeadersTool,
    RobotsSitemapTool,
)


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    for tool in (HttpRequestTool(), InspectHeadersTool(), RobotsSitemapTool(), DecodeEncodeTool()):
        reg.register(tool)
    return reg


def test_decode_encode_operations():
    tool = DecodeEncodeTool()
    ctx = ToolContext()
    assert tool.run({"op": "base64-encode", "value": "hi"}, ctx) == "aGk="
    assert tool.run({"op": "base64-decode", "value": "aGk="}, ctx) == "hi"
    assert tool.run({"op": "url-encode", "value": "a b&c"}, ctx) == "a%20b%26c"
    assert tool.run({"op": "url-decode", "value": "a%20b"}, ctx) == "a b"
    assert tool.run({"op": "hex-encode", "value": "hi"}, ctx) == "6869"
    assert tool.run({"op": "hex-decode", "value": "6869"}, ctx) == "hi"


def test_decode_encode_is_local_and_safe():
    assert DecodeEncodeTool().touches_network is False


def test_jwt_decode_exposes_claims():
    tool = DecodeEncodeTool()
    # header {"alg":"none"} . payload {"admin":true} . (no signature)
    token = "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0."
    out = tool.run({"op": "jwt-decode", "value": token}, ToolContext())
    assert '"alg": "none"' in out
    assert '"admin": true' in out
    assert "signature not verified" in out


def test_http_request_is_mutating_and_gated():
    reg = _registry()
    ctx = ToolContext(authorized_targets=set())
    result = reg.execute(
        ToolCall(id="c", name="http_request", arguments={"url": "http://evil.example/"}), ctx
    )
    assert not result.ok and "not authorized" in result.log
    assert HttpRequestTool().mutating is True


def test_inspect_headers_flags_missing(mock_server):
    reg = _registry()
    ctx = ToolContext()  # localhost always allowed
    result = reg.execute(
        ToolCall(id="c", name="inspect_headers", arguments={"url": mock_server}), ctx
    )
    assert result.ok
    assert "MISSING" in result.log and "content-security-policy" in result.log


def test_fetch_robots_sitemap(mock_server):
    reg = _registry()
    result = reg.execute(
        ToolCall(id="c", name="fetch_robots_sitemap", arguments={"url": mock_server}),
        ToolContext(),
    )
    assert result.ok
    assert "robots.txt" in result.log and "sitemap.xml" in result.log
