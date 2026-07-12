"""Tool protocol, execution context, and registry.

A tool is a named, schema-described, runnable action that returns a **log** (a string).
The registry holds tools, emits their schemas for the system prompt, and executes a
``ToolCall`` into a ``ToolResult`` — catching errors so a misbehaving tool degrades to a
failed result instead of crashing the loop.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from ai_framework.agent.contracts import ToolCall, ToolResult
from ai_framework.harness.contracts import RulesOfEngagement

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ToolContext(BaseModel):
    """What a tool is allowed to know at execution time (the safety surface).

    Besides the scope allow-list, it carries *injectable collaborators* so tools stay pure and
    unit-testable: ``session`` (a stateful HTTP opener with a cookie jar / proxy / User-Agent),
    ``runner`` (a subprocess executor for external CLIs), and ``renderer`` (a headless browser).
    All default to ``None`` — a tool then falls back to its own real, stdlib implementation.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    authorized_targets: set[str] = Field(default_factory=set)
    # When set, this exact operator-owned RoE is enforced in ``ToolRegistry.execute`` in
    # addition to the legacy host allow-list below. ``primary_target`` supplies scope context to
    # local credential-setup tools, which do not otherwise carry a URL argument.
    rules_of_engagement: RulesOfEngagement | None = None
    primary_target: str = ""
    approved_action_tokens: set[str] = Field(default_factory=set)
    limiter: Any = None  # EngagementLimiter; optional to keep contexts easily injectable
    audit: Any = None  # EvidenceLedger; records redacted tool decisions and outputs
    run_id: str = ""
    session: Any = None  # HttpSession — persistent cookies / proxy / UA (see tools/session.py)
    runner: Any = None  # (argv, timeout) -> (rc, stdout, stderr); injected in tests
    renderer: Any = None  # (url, wait_ms) -> rendered HTML; injected in tests
    workspace: str = ""  # optional dir for tool output artifacts


def require_authorized(url: str, ctx: ToolContext) -> str:
    """Return the host, or raise if it is neither localhost nor an authorized target.

    The single choke point every network tool goes through, so the scope gate can never be
    forgotten when a new tool is added (ARCHITECTURE.md › Safety).
    """
    if ctx.rules_of_engagement is not None:
        from ai_framework.harness.policy import target_is_in_scope

        if not target_is_in_scope(url, ctx.rules_of_engagement):
            raise PermissionError("target is excluded or outside the Rules of Engagement scope")
    return require_authorized_host(urlparse(url).hostname or "", ctx)


def require_authorized_host(host: str, ctx: ToolContext) -> str:
    """Scope-gate a bare host/domain (external tools take a host, not a URL).

    Localhost is always allowed; any other host must be listed in ``authorized_targets``. A
    target is also allowed when it is a subdomain of an authorized apex, so ``subfinder``-style
    enumeration of an authorized domain does not trip the gate.
    """
    host = (host or "").strip().lower()
    if ctx.rules_of_engagement is not None:
        from ai_framework.harness.policy import target_is_in_scope

        if target_is_in_scope(host, ctx.rules_of_engagement):
            return host
        raise PermissionError("target is excluded or outside the Rules of Engagement scope")
    if host in LOCAL_HOSTS:
        return host
    for allowed in ctx.authorized_targets:
        a = allowed.strip().lower()
        if host == a or host.endswith("." + a):
            return host
    raise PermissionError(
        f"target not authorized: {host!r} (authorize it in RunConfig.authorized_targets)"
    )


def tool_is_mutating(tool: Any, args: dict[str, Any]) -> bool:
    """Whether executing ``tool`` with ``args`` changes target state.

    A tool may be mutating per-call (e.g. ``run_recon`` is passive for httpx but intrusive for
    nuclei) by exposing ``is_mutating_call(args)``; otherwise its static ``mutating`` flag wins.
    """
    hook = getattr(tool, "is_mutating_call", None)
    if callable(hook):
        return bool(hook(args))
    return bool(getattr(tool, "mutating", False))


@runtime_checkable
class Tool(Protocol):
    """A runnable action. Implementations return the log string from ``run``."""

    name: str
    description: str

    @property
    def json_schema(self) -> dict[str, Any]:
        """JSON Schema for this tool's ``arguments`` object."""
        ...

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        """Execute and return the log. Raise on failure; the registry records it."""
        ...


class ToolRegistry:
    """Holds tools, exposes their schemas, and executes calls safely."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def schemas(self) -> list[dict[str, Any]]:
        """Schemas for the system prompt / backend tool declarations."""
        return [
            {"name": t.name, "description": t.description, "input_schema": t.json_schema}
            for t in self._tools.values()
        ]

    def execute(self, call: ToolCall, ctx: ToolContext) -> ToolResult:
        tool = self._tools.get(call.name)
        if tool is None:
            result = ToolResult(call_id=call.id, log=f"unknown tool: {call.name}", ok=False)
            if ctx.audit is not None:
                ctx.audit.record_tool(call, result, ctx)
            return result
        acquired = False
        try:
            # Runtime-enforce the optional professional Rules of Engagement before a tool can
            # touch the target. This complements (rather than replaces) each tool's own scope
            # gate, which is intentionally retained as defense in depth.
            from ai_framework.harness.runtime import enforce_tool_policy

            enforce_tool_policy(call, tool, ctx)
            if ctx.limiter is not None:
                acquired = bool(ctx.limiter.before(call, tool))
            log = tool.run(call.arguments, ctx)
            result = ToolResult(call_id=call.id, log=log, ok=True)
        except Exception as exc:  # noqa: BLE001 - degrade, don't crash the loop
            result = ToolResult(call_id=call.id, log=f"{type(exc).__name__}: {exc}", ok=False)
        finally:
            if ctx.limiter is not None:
                ctx.limiter.after(acquired)
        if ctx.audit is not None:
            ctx.audit.record_tool(call, result, ctx)
        return result
