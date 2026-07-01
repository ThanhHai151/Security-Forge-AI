"""browser_render: scope gate, injected renderer, truncation, graceful missing engine."""

import pytest

from ai_framework.tools.base import ToolContext
from ai_framework.tools.browser import BrowserRenderTool

TOOL = BrowserRenderTool()


def test_uses_injected_renderer_and_returns_dom():
    seen = {}

    def renderer(url, wait_ms):
        seen["url"] = url
        seen["wait_ms"] = wait_ms
        return "<html><body id='x'>rendered!</body></html>"

    ctx = ToolContext(authorized_targets={"example.com"}, renderer=renderer)
    out = TOOL.run({"url": "https://example.com/app", "wait_ms": 500}, ctx)
    assert seen == {"url": "https://example.com/app", "wait_ms": 500}
    assert "rendered!" in out


def test_off_scope_is_blocked():
    ctx = ToolContext(authorized_targets={"example.com"}, renderer=lambda u, w: "x")
    with pytest.raises(PermissionError):
        TOOL.run({"url": "https://evil.com"}, ctx)


def test_missing_playwright_degrades_gracefully():
    def missing(url, wait_ms):
        raise ImportError("No module named 'playwright'")

    ctx = ToolContext(authorized_targets={"example.com"}, renderer=missing)
    out = TOOL.run({"url": "https://example.com"}, ctx)
    assert "not installed" in out.lower()


def test_render_failure_is_caught():
    def boom(url, wait_ms):
        raise RuntimeError("navigation timeout")

    ctx = ToolContext(authorized_targets={"example.com"}, renderer=boom)
    out = TOOL.run({"url": "https://example.com"}, ctx)
    assert "render failed" in out


def test_output_truncated():
    ctx = ToolContext(authorized_targets={"example.com"}, renderer=lambda u, w: "Z" * 50000)
    out = TOOL.run({"url": "https://example.com"}, ctx)
    assert "truncated" in out and len(out) < 50000
