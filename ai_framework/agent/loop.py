"""The Hermes loop: observe -> reason -> act -> observe, with log-driven planning.

For a goal+target, repeatedly ask the backend for an action, execute its tool calls, record
the logs, then ask the backend to plan the next step from those logs — and feed that plan
back in so it *drives* the next action, until the backend signals done or a budget/guardrail
stops it. Optional collaborators (all off by default so the offline demo stays minimal):

* ``memory``    — persist facts/attempts and suppress known dead ends (anti-loop). Step 5.
* ``budget``    — Headroom: shape the request to fit the context window.
* ``guardrail`` — break failure/no-progress loops before they burn the step budget.
* ``pacer``     — OPSEC pacing between network actions (min interval + jitter).
* ``findings``  — persist structured findings captured via ``note_finding`` for the report.
* ``on_turn``   — checkpoint callback fired after each turn (durable runs).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import urlparse

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
from ai_framework.agent.guardrails import GuardrailController
from ai_framework.agent.opsec import Pacer
from ai_framework.agent.system import build_system_prompt, with_memory, with_plan
from ai_framework.headroom import TurnRequest, fit
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import Backend
from ai_framework.notes.contracts import Finding, Severity
from ai_framework.notes.store import JsonlFindingStore
from ai_framework.tools.base import ToolContext, ToolRegistry

# Top-K recalled into context when Headroom is off (Headroom uses budget.memory_recall_k).
DEFAULT_RECALL_K = 5


def _body(call: ToolCall) -> str:
    return json.dumps(call.arguments, sort_keys=True)


def _touches_network(registry: ToolRegistry, name: str) -> bool:
    try:
        return bool(getattr(registry.get(name), "touches_network", True))
    except KeyError:
        return False


def _record_finding(
    findings: JsonlFindingStore, run: Run, config: RunConfig, step: int, call: ToolCall
) -> None:
    args = call.arguments
    findings.write(
        Finding(
            run_id=run.id,
            target=config.target,
            step=step,
            title=str(args.get("title", "")),
            detail=str(args.get("detail", "")),
            severity=Severity.parse(args.get("severity")),
            evidence=str(args.get("evidence", "")),
            kb_ref=str(args.get("kb_ref", "")),
            tags=[str(t) for t in (args.get("tags") or [])],
        )
    )


def run_loop(
    config: RunConfig,
    backend: Backend,
    registry: ToolRegistry,
    memory: JsonlMemoryStore | None = None,
    budget: Budget | None = None,
    run: Run | None = None,
    guardrail: GuardrailController | None = None,
    pacer: Pacer | None = None,
    findings: JsonlFindingStore | None = None,
    on_turn: Callable[[Run], None] | None = None,
) -> Run:
    tools = registry.schemas()
    base_system = build_system_prompt(config, tools)
    ctx = ToolContext(authorized_targets=config.authorized_targets)
    target_host = urlparse(config.target).hostname or config.target
    # Accept a caller-owned Run so an async service can poll its transcript as it grows.
    if run is None:
        run = Run(config=config)

    for i in range(config.step_budget):
        # Recall relevant memory and inject it into the system prompt so the model
        # actually uses what it has learned (Step 5). Done every turn since memory grows.
        recall_k = budget.memory_recall_k if budget is not None else DEFAULT_RECALL_K
        recalled = memory.recall(config.target, "", recall_k) if memory else []
        # Feed the previous turn's plan forward so planning steers this action (not discarded).
        last_plan = run.transcript[-1].next_plan if run.transcript else ""

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
            call_system = with_plan(with_memory(fitted.system, fitted.memory), last_plan)
            action = backend.act(call_system, fitted.transcript, config, fitted.tools)
        else:
            call_system = with_plan(with_memory(base_system, recalled), last_plan)
            action = backend.act(call_system, run.transcript, config, tools)
        if action.done:
            run.outcome = "done"
            break

        results: list[ToolResult] = []
        for call in action.tool_calls:
            body = _body(call)

            # Guardrail: refuse a call that has proven to be a dead end this run.
            if guardrail is not None:
                decision = guardrail.check(call, registry)
                if not decision.allow:
                    results.append(
                        ToolResult(
                            call_id=call.id, log=f"guardrail: {decision.reason}", ok=False
                        )
                    )
                    continue

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

            # OPSEC: pace network actions so the cadence isn't a perfect beacon.
            if pacer is not None and _touches_network(registry, call.name):
                pacer.wait(target_host)

            result = registry.execute(call, ctx)
            results.append(result)

            if guardrail is not None:
                guardrail.record(call, result.ok)
            if findings is not None and call.name == "note_finding" and result.ok:
                _record_finding(findings, run, config, i, call)

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

        if on_turn is not None:
            on_turn(run)

        if guardrail is not None:
            guardrail.observe_turn(any(r.ok for r in results))
            if guardrail.should_halt():
                run.outcome = "guardrail_halt"
                run.error = guardrail.halt_reason
                break
    else:
        run.outcome = "step_budget_reached"

    return run
