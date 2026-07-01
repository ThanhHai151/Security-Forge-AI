"""The Hermes loop: observe -> reason -> act -> observe, with log-driven planning.

For a goal+target, repeatedly ask the backend for an action, execute its tool calls,
record the logs, then ask the backend to plan the next step from those logs — until the
backend signals done or the step budget is reached. Optionally persists to memory and
suppresses known dead-end attempts (anti-loop). See Step 4 + Step 5.
"""

from __future__ import annotations

import json

from ai_framework.agent.contracts import (
    Budget,
    MemoryKind,
    MemoryRecord,
    Run,
    RunConfig,
    ToolCall,
    ToolResult,
    Turn,
)
from ai_framework.agent.system import build_system_prompt, with_memory
from ai_framework.headroom import TurnRequest, fit
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import Backend
from ai_framework.tools.base import ToolContext, ToolRegistry

# Top-K recalled into context when Headroom is off (Headroom uses budget.memory_recall_k).
DEFAULT_RECALL_K = 5


def _body(call: ToolCall) -> str:
    return json.dumps(call.arguments, sort_keys=True)


def run_loop(
    config: RunConfig,
    backend: Backend,
    registry: ToolRegistry,
    memory: JsonlMemoryStore | None = None,
    budget: Budget | None = None,
    run: Run | None = None,
) -> Run:
    tools = registry.schemas()
    base_system = build_system_prompt(config, tools)
    ctx = ToolContext(authorized_targets=config.authorized_targets)
    # Accept a caller-owned Run so an async service can poll its transcript as it grows.
    if run is None:
        run = Run(config=config)

    for i in range(config.step_budget):
        # Recall relevant memory and inject it into the system prompt so the model
        # actually uses what it has learned (Step 5). Done every turn since memory grows.
        recall_k = budget.memory_recall_k if budget is not None else DEFAULT_RECALL_K
        recalled = memory.recall(config.target, "", recall_k) if memory else []

        if budget is not None:
            # Headroom: shape what reaches the backend so the call stays inside the window
            # with reserved output headroom. It may shrink the recalled memory to fit.
            fitted = fit(
                TurnRequest(
                    system=base_system,
                    transcript=run.transcript,
                    tools=tools,
                    memory=recalled,
                ),
                budget,
            )
            run.compaction_reports.append(fitted.report)
            call_system = with_memory(fitted.system, fitted.memory)
            action = backend.act(call_system, fitted.transcript, config, fitted.tools)
        else:
            call_system = with_memory(base_system, recalled)
            action = backend.act(call_system, run.transcript, config, tools)
        if action.done:
            run.outcome = "done"
            break

        results: list[ToolResult] = []
        for call in action.tool_calls:
            body = _body(call)
            # Anti-loop: skip a call that already failed with identical args.
            if memory and memory.has_failed_attempt(config.target, call.name, body):
                results.append(
                    ToolResult(
                        call_id=call.id,
                        log=f"skipped: known dead end ({call.name} {body})",
                        ok=False,
                    )
                )
                continue

            result = registry.execute(call, ctx)
            results.append(result)

            if memory:
                kind = MemoryKind.target_fact if result.ok else MemoryKind.attempt
                memory.write(
                    MemoryRecord(
                        id=f"{call.id}",
                        kind=kind,
                        target=config.target,
                        technique=call.name,
                        body=body if not result.ok else result.log[:500],
                    )
                )

        turn = Turn(
            index=i,
            reasoning=action.reasoning,
            tool_calls=action.tool_calls,
            tool_results=results,
        )
        run.transcript.append(turn)
        turn.next_plan = backend.plan(call_system, run.transcript, config)
    else:
        run.outcome = "step_budget_reached"

    return run
