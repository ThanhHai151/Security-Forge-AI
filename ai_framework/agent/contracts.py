"""Data contracts for the Hermes turn protocol and persistent memory.

These pydantic models are the wire format for the whole loop: every turn, tool call,
tool result, and memory record round-trips through JSON so a run can be logged, diffed,
and replayed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from ai_framework.harness.contracts import RulesOfEngagement


def _now() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return uuid4().hex


# --- Turn protocol (§2.2) ---------------------------------------------------


class ToolCall(BaseModel):
    """A single structured action the model wants to take."""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    """The output (the pentest LOG) of executing one ToolCall."""

    call_id: str
    log: str
    ok: bool = True


class Turn(BaseModel):
    """One iteration of the observe -> reason -> act -> observe loop."""

    index: int
    reasoning: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    next_plan: str = ""


# --- Memory (§2.4) ----------------------------------------------------------


class MemoryKind(StrEnum):
    target_fact = "target_fact"
    attempt = "attempt"
    lesson = "lesson"


class MemoryRecord(BaseModel):
    """A durable fact the agent keeps across steps and sessions."""

    id: str
    kind: MemoryKind
    created_at: datetime = Field(default_factory=_now)
    target: str = ""
    technique: str = ""
    body: str = ""


# --- Run configuration ------------------------------------------------------


class RunConfig(BaseModel):
    """Inputs that define and bound a single agent run."""

    goal: str
    target: str
    step_budget: int = 10
    backend: str = "offline"
    # Optional model id + base URL for the chosen backend (e.g. a 9router/Antigravity
    # proxy model). When omitted, each backend falls back to its own default/env.
    model: str | None = None
    base_url: str | None = None
    authorized_targets: set[str] = Field(default_factory=set)
    # Optional professional engagement control plane. When present, every autonomous tool call
    # is checked against its authorization, scope, testing window, action gate, and approval
    # requirements before execution; see ``ai_framework.harness.runtime``.
    rules_of_engagement: RulesOfEngagement | None = None
    # OPSEC pacing: minimum seconds between network actions to the same host, plus up to
    # this many seconds of random jitter. 0 = fire as fast as possible (default, so tests
    # and the offline demo stay instant). Raise it to behave like a cautious operator.
    opsec_min_interval: float = 0.0
    opsec_jitter: float = 0.0
    # OPSEC transport: route every network tool through this proxy (e.g. "http://127.0.0.1:8080"
    # for Burp, or a SOCKS-over-HTTP pivot) and/or present a custom User-Agent. Empty = direct.
    proxy: str | None = None
    user_agent: str | None = None
    # Privacy: when True, refuse to use any remote model provider (only the offline backend is
    # allowed) so no target-derived prompt text ever leaves the host. Also settable process-wide
    # via SECFORGE_LOCAL_ONLY=1 (enforced in the backend factory).
    local_only: bool = False


class Run(BaseModel):
    """A completed (or in-progress) run: config + ordered transcript + outcome."""

    id: str = Field(default_factory=_new_id)
    config: RunConfig
    transcript: list[Turn] = Field(default_factory=list)
    # "incomplete" while running, then "done" / "step_budget_reached" / "guardrail_halt" /
    # "error".
    outcome: str = "incomplete"
    # Populated when ``outcome == "error"`` (e.g. proxy unreachable, missing API key).
    error: str = ""
    # One Headroom compaction report per fitted model call (empty when Headroom is off).
    compaction_reports: list[CompactionReport] = Field(default_factory=list)


# --- Headroom: context-window budgeting & compaction ----


class Budget(BaseModel):
    """Per-run context budget. ``input_budget`` is what Headroom must fit into; the rest
    of the window is reserved output ``headroom`` the input must never consume (§3.2)."""

    context_window: int = 200_000
    reserved_output_headroom: int = 50_000
    # Compaction knobs (§3.5).
    memory_recall_k: int = 5
    keep_recent_turns: int = 2
    max_tool_log_tokens: int = 400

    @property
    def input_budget(self) -> int:
        """Tokens available for assembled input after reserving output headroom."""
        return max(0, self.context_window - self.reserved_output_headroom)

    @classmethod
    def from_window(cls, context_window: int, reserved_fraction: float = 0.25, **kw: Any) -> Budget:
        """Reserve ``reserved_fraction`` of the window for output (default 25%, §3.5)."""
        return cls(
            context_window=context_window,
            reserved_output_headroom=int(context_window * reserved_fraction),
            **kw,
        )


class CompactionAction(BaseModel):
    """One step taken to fit the request, recorded so nothing is lost silently (§3.3)."""

    kind: str  # drop_reasoning | summarize_turns | shrink_memory | truncate_log
    detail: str
    tokens_saved: int = 0


class CompactionReport(BaseModel):
    """What Headroom did for one model call. Surfaced to the API/console (§3.4)."""

    input_budget: int
    tokens_before: int
    tokens_after: int
    within_budget: bool
    actions: list[CompactionAction] = Field(default_factory=list)
