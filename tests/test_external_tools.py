"""run_recon: scope-gate, argv building, injectable runner, per-call intrusiveness."""

import pytest

from ai_framework.tools.base import ToolContext, tool_is_mutating
from ai_framework.tools.external import ExternalReconTool, is_mutating_call


def _ctx(runner=None, targets=("example.com",)):
    return ToolContext(authorized_targets=set(targets), runner=runner)


def _capture():
    """A fake runner that records the argv it was handed and returns canned output."""
    seen = {}

    def runner(argv, timeout):
        seen["argv"] = argv
        seen["timeout"] = timeout
        return 0, "scan-output-here", ""

    return runner, seen


def test_builds_expected_argv_and_returns_output():
    runner, seen = _capture()
    tool = ExternalReconTool()
    out = tool.run({"tool": "httpx", "target": "https://example.com/app"}, _ctx(runner))
    assert seen["argv"] == ["httpx", "-silent", "-u", "https://example.com/app"]
    assert "scan-output-here" in out and "exit 0" in out


def test_off_scope_target_is_blocked():
    tool = ExternalReconTool()
    with pytest.raises(PermissionError):
        tool.run({"tool": "httpx", "target": "https://evil.com"}, _ctx(targets=("example.com",)))


def test_extra_args_cannot_smuggle_an_off_scope_host():
    runner, _ = _capture()
    tool = ExternalReconTool()
    with pytest.raises(PermissionError):
        tool.run(
            {"tool": "nmap", "target": "example.com", "extra_args": ["--script", "http-title",
                                                                     "evil.com"]},
            _ctx(runner),
        )


def test_subdomain_of_authorized_apex_is_allowed():
    runner, seen = _capture()
    tool = ExternalReconTool()
    tool.run({"tool": "httpx", "target": "https://api.example.com"}, _ctx(runner))
    assert seen["argv"][-1] == "https://api.example.com"


def test_ffuf_requires_a_wordlist():
    tool = ExternalReconTool()
    with pytest.raises(ValueError, match="wordlist"):
        tool.run({"tool": "ffuf", "target": "https://example.com"}, _ctx(lambda a, t: (0, "", "")))


def test_ffuf_with_wordlist_injects_fuzz_and_list():
    runner, seen = _capture()
    tool = ExternalReconTool()
    tool.run({"tool": "ffuf", "target": "https://example.com", "wordlist": "/wl.txt"}, _ctx(runner))
    assert "https://example.com/FUZZ" in seen["argv"]
    assert "/wl.txt" in seen["argv"]


def test_unknown_tool_rejected():
    tool = ExternalReconTool()
    with pytest.raises(ValueError, match="unknown tool"):
        tool.run({"tool": "rm-rf", "target": "example.com"}, _ctx(lambda a, t: (0, "", "")))


def test_missing_binary_degrades_gracefully_without_runner():
    # No injected runner + a binary that is not installed → a clear message, not a crash.
    tool = ExternalReconTool()
    out = tool.run({"tool": "nuclei", "target": "https://example.com"}, _ctx(runner=None))
    assert "not installed" in out.lower()


def test_runner_error_is_caught_as_not_installed():
    def boom(argv, timeout):
        raise FileNotFoundError(argv[0])

    tool = ExternalReconTool()
    out = tool.run({"tool": "httpx", "target": "https://example.com"}, _ctx(boom))
    assert "not installed" in out.lower()


def test_output_is_truncated():
    runner = lambda argv, timeout: (0, "A" * 20000, "")  # noqa: E731
    tool = ExternalReconTool()
    out = tool.run({"tool": "httpx", "target": "https://example.com"}, _ctx(runner))
    assert "truncated" in out and len(out) < 20000


def test_per_call_intrusiveness():
    assert is_mutating_call({"tool": "nuclei"}) is True
    assert is_mutating_call({"tool": "sqlmap"}) is True
    assert is_mutating_call({"tool": "httpx"}) is False
    # And the loop/guardrail helper honours the per-call hook.
    tool = ExternalReconTool()
    assert tool_is_mutating(tool, {"tool": "nuclei"}) is True
    assert tool_is_mutating(tool, {"tool": "subfinder"}) is False
