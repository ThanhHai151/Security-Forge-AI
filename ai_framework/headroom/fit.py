"""``fit(request, budget) -> FittedRequest`` — the Headroom contract (§3.4).

Assemble the model input, and if it would eat into reserved output headroom, compact it
along the fixed priority ladder (§3.3):

  1. drop oldest reasoning/scratchpad segments      (cheapest to lose)
  2. summarize older turns into a rolling synopsis   (kept, not dropped)
  3. shrink memory recall to a smaller top-K
  4. truncate large tool logs to head+tail           (last resort)

It never changes the *meaning* of the turn protocol — only what is included and how
densely. Every action is recorded in the returned ``CompactionReport`` (§3.4: no silent
loss).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ai_framework.agent.contracts import (
    Budget,
    CompactionAction,
    CompactionReport,
    MemoryRecord,
    Turn,
)
from ai_framework.headroom.budget import (
    count_tokens,
    memory_tokens,
    tools_tokens,
    turn_tokens,
)
from ai_framework.headroom.compress import compress_log

_SYNOPSIS_HEADER = "Prior context (summarized by Headroom):"


class TurnRequest(BaseModel):
    """Everything the loop wants to send to the backend for one model call."""

    system: str
    transcript: list[Turn] = Field(default_factory=list)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    memory: list[MemoryRecord] = Field(default_factory=list)


class FittedRequest(BaseModel):
    """What actually goes to the backend, plus a record of how it was shaped.

    ``system`` already has the rolling ``synopsis`` folded in, so a backend that only
    accepts (system, transcript, tools) needs no awareness of Headroom.
    """

    system: str
    transcript: list[Turn] = Field(default_factory=list)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    memory: list[MemoryRecord] = Field(default_factory=list)
    synopsis: str = ""
    report: CompactionReport


def _summarize_turn(turn: Turn) -> str:
    actions = ", ".join(tc.name for tc in turn.tool_calls) or "no action"
    ok = sum(1 for r in turn.tool_results if r.ok)
    plan = turn.next_plan.strip() or "(no plan)"
    return f"- turn {turn.index}: {actions} ({ok}/{len(turn.tool_results)} ok); plan: {plan}"


def fit(request: TurnRequest, budget: Budget) -> FittedRequest:
    system = request.system
    tools = request.tools
    memory = list(request.memory)
    turns = [t.model_copy(deep=True) for t in request.transcript]
    synopsis_lines: list[str] = []
    actions: list[CompactionAction] = []

    def synopsis_text() -> str:
        if not synopsis_lines:
            return ""
        return _SYNOPSIS_HEADER + "\n" + "\n".join(synopsis_lines)

    def total() -> int:
        t = count_tokens(system) + count_tokens(synopsis_text()) + tools_tokens(tools)
        t += memory_tokens(memory)
        t += sum(turn_tokens(turn) for turn in turns)
        return t

    limit = budget.input_budget
    before = total()

    # The most recent turns are always kept intact; compaction works on the older prefix.
    def older_prefix() -> int:
        return max(0, len(turns) - budget.keep_recent_turns)

    # --- 1. Drop oldest reasoning/scratchpad segments --------------------------------
    if total() > limit:
        saved = 0
        for turn in turns[: older_prefix()]:
            if turn.reasoning:
                saved += turn_tokens(turn) - turn_tokens(
                    turn.model_copy(update={"reasoning": ""})
                )
                turn.reasoning = ""
        if saved:
            actions.append(
                CompactionAction(
                    kind="drop_reasoning",
                    detail=f"cleared reasoning on {older_prefix()} older turn(s)",
                    tokens_saved=saved,
                )
            )

    # --- 2. Summarize older turns into a rolling synopsis ----------------------------
    while total() > limit and older_prefix() > 0:
        turn = turns.pop(0)
        saved = turn_tokens(turn)
        line = _summarize_turn(turn)
        synopsis_lines.append(line)
        saved -= count_tokens(line)
        actions.append(
            CompactionAction(
                kind="summarize_turns",
                detail=f"summarized turn {turn.index} into synopsis",
                tokens_saved=max(0, saved),
            )
        )

    # --- 3. Shrink memory recall -----------------------------------------------------
    while total() > limit and memory:
        dropped = memory.pop()  # recall is pre-sorted best-first; drop the weakest
        actions.append(
            CompactionAction(
                kind="shrink_memory",
                detail=f"dropped memory {dropped.id} ({dropped.kind})",
                tokens_saved=count_tokens(dropped.body) + count_tokens(dropped.technique),
            )
        )

    # --- 4. Compress large tool logs (last resort) -----------------------------------
    # compress_log collapses repetition losslessly before any head/tail truncation, so we
    # keep more signal per token than a blind cut.
    if total() > limit:
        for turn in turns:
            for result in turn.tool_results:
                new_log, saved = compress_log(result.log, budget.max_tool_log_tokens)
                if saved:
                    result.log = new_log
                    actions.append(
                        CompactionAction(
                            kind="truncate_log",
                            detail=f"compressed log for call {result.call_id}",
                            tokens_saved=saved,
                        )
                    )
            if total() <= limit:
                break

    synopsis = synopsis_text()
    fitted_system = f"{system}\n\n{synopsis}" if synopsis else system
    after = total()
    report = CompactionReport(
        input_budget=limit,
        tokens_before=before,
        tokens_after=after,
        within_budget=after <= limit,
        actions=actions,
    )
    return FittedRequest(
        system=fitted_system,
        transcript=turns,
        tools=tools,
        memory=memory,
        synopsis=synopsis,
        report=report,
    )
