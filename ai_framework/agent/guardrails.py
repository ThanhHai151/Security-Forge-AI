"""Tool-call guardrails: break failure/no-progress loops before they burn the budget.

A hermes-agent-style, side-effect-free controller. The loop asks ``check()`` before running
a call and feeds every result back via ``record()``; ``observe()`` tallies whole-turn
progress. The controller only *decides* — the loop applies the decision — so it stays pure
and trivially testable.

Two ideas do the heavy lifting:

* **Idempotent vs. mutating.** Recon (``http_get``, decoders) is safe to retry, so it gets a
  long leash. A *mutating* call — one that changes target state (a write, a non-GET request,
  an injection probe) — is held to a much tighter one: a stuck run must not keep poking the
  target. Tools advertise this with a ``mutating`` attribute (default ``False``).
* **No progress = stop.** If several turns pass with no successful tool call, the run is
  spinning; halt it instead of exhausting the step budget against a dead end.
"""

from __future__ import annotations

import json
from collections import defaultdict

from pydantic import BaseModel

from ai_framework.agent.contracts import ToolCall
from ai_framework.tools.base import ToolRegistry, tool_is_mutating


class GuardrailConfig(BaseModel):
    """Thresholds for the loop-breaker. Defaults are deliberately lenient."""

    # Block a call once the identical (name, args) has failed this many times this run.
    exact_failure_block_after: int = 3
    # Block any further use of a tool after this many consecutive failures.
    same_tool_halt_after: int = 6
    # A mutating tool is cut off far sooner — don't keep changing state blindly.
    mutating_failure_block_after: int = 2
    # Halt the whole run after this many turns with no successful tool call.
    no_progress_halt_after: int = 5


class Decision(BaseModel):
    """The controller's verdict for one prospective call."""

    allow: bool = True
    reason: str = ""


def _body(call: ToolCall) -> str:
    return json.dumps(call.arguments, sort_keys=True)


def _is_mutating(call: ToolCall, registry: ToolRegistry) -> bool:
    try:
        return tool_is_mutating(registry.get(call.name), call.arguments)
    except KeyError:
        return False


class GuardrailController:
    """Tracks failure/progress signals for a single run and rules on each call."""

    def __init__(self, config: GuardrailConfig | None = None) -> None:
        self.config = config or GuardrailConfig()
        self._exact_fail: dict[tuple[str, str], int] = defaultdict(int)
        self._tool_fail: dict[str, int] = defaultdict(int)  # consecutive, reset on success
        self._turns_without_progress = 0
        self._halt_reason = ""

    def check(self, call: ToolCall, registry: ToolRegistry) -> Decision:
        """Rule on a call *before* it runs, from what has failed so far this run."""
        cfg = self.config
        name, body = call.name, _body(call)

        if self._exact_fail[(name, body)] >= cfg.exact_failure_block_after:
            return Decision(allow=False, reason=f"identical {name} call failed repeatedly")

        mutating = _is_mutating(call, registry)
        limit = cfg.mutating_failure_block_after if mutating else cfg.same_tool_halt_after
        if self._tool_fail[name] >= limit:
            kind = "mutating " if mutating else ""
            return Decision(allow=False, reason=f"{kind}tool {name} keeps failing")

        return Decision(allow=True)

    def record(self, call: ToolCall, ok: bool) -> None:
        """Fold one executed call's outcome back into the counters."""
        name, body = call.name, _body(call)
        if ok:
            self._tool_fail[name] = 0
        else:
            self._exact_fail[(name, body)] += 1
            self._tool_fail[name] += 1

    def observe_turn(self, any_ok: bool) -> None:
        """After a turn, track whether the run is still making progress."""
        if any_ok:
            self._turns_without_progress = 0
        else:
            self._turns_without_progress += 1
            if self._turns_without_progress >= self.config.no_progress_halt_after:
                self._halt_reason = (
                    f"no successful action in {self._turns_without_progress} turns"
                )

    def should_halt(self) -> bool:
        return bool(self._halt_reason)

    @property
    def halt_reason(self) -> str:
        return self._halt_reason
