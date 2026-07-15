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
* ``cancel``    — a ``threading.Event`` an operator can set to stop the loop early (Stop button).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from ai_framework.agent.assets import Asset, JsonlAssetStore
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
from ai_framework.agent.verify import FindingVerifier
from ai_framework.evidence import EvidenceLedger
from ai_framework.harness.limits import EngagementLimiter
from ai_framework.harness.netguard import EgressPolicy
from ai_framework.headroom import TurnRequest, fit
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import Backend
from ai_framework.notes.contracts import Confidence, Finding, FindingStatus, Severity
from ai_framework.notes.store import JsonlFindingStore
from ai_framework.tools.base import ToolContext, ToolRegistry, require_authorized, tool_is_mutating
from ai_framework.tools.session import HttpSession

# Top-K recalled into context when Headroom is off (Headroom uses budget.memory_recall_k).
DEFAULT_RECALL_K = 5


def _body(call: ToolCall) -> str:
    return json.dumps(call.arguments, sort_keys=True)


def _touches_network(registry: ToolRegistry, name: str) -> bool:
    try:
        return bool(getattr(registry.get(name), "touches_network", True))
    except KeyError:
        return False


def _is_mutating(registry: ToolRegistry, name: str, args: dict) -> bool:
    try:
        return tool_is_mutating(registry.get(name), args)
    except KeyError:
        return False


def _record_finding(
    findings: JsonlFindingStore,
    run: Run,
    config: RunConfig,
    step: int,
    call: ToolCall,
    ctx: ToolContext,
    verifier: FindingVerifier | None,
) -> None:
    args = call.arguments
    verified, verification = False, "unverified (no repro provided)"
    repro = args.get("repro")
    if isinstance(repro, dict) and repro and verifier is not None:
        verified, verification = verifier.verify(repro, ctx)
    kb_ref = str(args.get("kb_ref", ""))
    tags = [str(t) for t in (args.get("tags") or [])]
    from vuln_search.mapping import mapping_for

    mapping = mapping_for(kb_ref or next((tag for tag in tags if mapping_for(tag)["cwe"]), ""))
    findings.write(
        Finding(
            run_id=run.id,
            target=config.target,
            step=step,
            title=str(args.get("title", "")),
            detail=str(args.get("detail", "")),
            severity=Severity.parse(args.get("severity")),
            evidence=str(args.get("evidence", "")),
            kb_ref=kb_ref,
            tags=tags,
            status=FindingStatus.reproduced if verified else FindingStatus.draft,
            confidence=Confidence.high if verified else Confidence.low,
            cvss_score=args.get("cvss_score"),
            cvss_vector=str(args.get("cvss_vector", "")),
            cwe=[str(x) for x in (args.get("cwe") or mapping["cwe"])],
            owasp=str(args.get("owasp") or mapping["owasp"]),
            wstg=[str(x) for x in (args.get("wstg") or mapping["wstg"])],
            attack=[str(x) for x in (args.get("attack") or mapping["attack"])],
            affected_assets=[str(x) for x in (args.get("affected_assets") or [])],
            remediation_owner=str(args.get("remediation_owner", "")),
            verified=verified,
            verification=verification,
        )
    )


def _record_assets(assets: JsonlAssetStore, config: RunConfig, step: int, call: ToolCall) -> None:
    args = call.arguments
    rows = args.get("assets")
    if not isinstance(rows, list):
        rows = [args]
    for r in rows:
        value = str(r.get("value", "")).strip()
        if not value:
            continue
        assets.write(
            Asset(
                target=config.target,
                kind=Asset.normalize_kind(r.get("kind")),
                value=value,
                detail=str(r.get("detail", "")),
                source=f"step {step}",
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
    hold_mutating: bool = False,
    on_hold: Callable[[ToolCall, str], None] | None = None,
    system_addon: str = "",
    verifier: FindingVerifier | None = None,
    assets: JsonlAssetStore | None = None,
    cancel: threading.Event | None = None,
    evidence: EvidenceLedger | None = None,
    limiter: EngagementLimiter | None = None,
    max_model_retries: int = 2,
    retry_sleep: Callable[[float], None] = time.sleep,
) -> Run:
    tools = registry.schemas()
    base_system = build_system_prompt(config, tools)
    if system_addon:
        base_system = f"{base_system}\n\n{system_addon}"
    # One session per run: cookies established by `login` persist across every later tool, and
    # the OPSEC proxy / User-Agent from the config are applied to all network traffic.
    ctx = ToolContext(
        authorized_targets=config.authorized_targets,
        rules_of_engagement=config.rules_of_engagement,
        primary_target=config.target,
        limiter=limiter
        or (
            EngagementLimiter(config.rules_of_engagement)
            if config.rules_of_engagement is not None
            else None
        ),
        audit=evidence,
    )

    def validate_redirect(url: str) -> None:
        require_authorized(url, ctx)

    roe = config.rules_of_engagement
    egress_policy = EgressPolicy(
        allow_private=bool(roe.allow_private_ranges) if roe is not None else False
    )
    session = HttpSession(
        user_agent=config.user_agent,
        proxy=config.proxy,
        # urllib follows redirects internally. Re-apply the same scope gate to every hop so an
        # in-scope URL cannot silently bounce the agent into an excluded/off-scope host.
        redirect_validator=validate_redirect,
        # Resolve-pin-and-gate direct egress: an in-scope name resolving/rebinding to a
        # private/metadata address is refused at connect time (RoE opts into private ranges).
        egress_policy=egress_policy,
    )
    ctx.session = session
    target_host = urlparse(config.target).hostname or config.target
    # Accept a caller-owned Run so an async service can poll its transcript as it grows.
    if run is None:
        run = Run(config=config)
    ctx.run_id = run.id

    def _with_retry(fn: Callable[[], Any]) -> Any:
        """Call a backend method with bounded exponential backoff on transient failure.

        A flaky provider (429/5xx/timeout/connection reset) should not abort the whole run on
        the first hiccup, and an exhausted-retries failure must terminate the loop in a defined,
        checkpointed ``error`` state — never bubble a raw exception out of the loop.
        """
        attempt = 0
        while True:
            try:
                return fn()
            except Exception:
                attempt += 1
                if attempt > max_model_retries:
                    raise
                retry_sleep(min(0.5 * (2 ** (attempt - 1)), 8.0))

    def _fit(transcript: list[Turn]) -> Any:
        assert budget is not None
        return fit(
            TurnRequest(system=base_system, transcript=transcript, tools=tools, memory=recalled),
            budget,
        )

    for i in range(config.step_budget):
        if cancel is not None and cancel.is_set():
            run.outcome = "stopped"
            break

        # Recall relevant memory and inject it into the system prompt so the model
        # actually uses what it has learned (Step 5). Done every turn since memory grows.
        recall_k = budget.memory_recall_k if budget is not None else DEFAULT_RECALL_K
        recalled = memory.recall(config.target, "", recall_k) if memory else []
        # Feed the previous turn's plan forward so planning steers this action (not discarded).
        last_plan = run.transcript[-1].next_plan if run.transcript else ""

        try:
            if budget is not None:
                # Headroom: shape what reaches the backend so the call stays inside the window
                # with reserved output headroom. It may shrink the recalled memory to fit.
                fitted = _fit(run.transcript)
                run.compaction_reports.append(fitted.report)
                call_system = with_plan(with_memory(fitted.system, fitted.memory), last_plan)
                action = _with_retry(
                    lambda cs=call_system, f=fitted: backend.act(
                        cs, f.transcript, config, f.tools
                    )
                )
            else:
                call_system = with_plan(with_memory(base_system, recalled), last_plan)
                action = _with_retry(
                    lambda cs=call_system: backend.act(cs, run.transcript, config, tools)
                )
        except Exception as exc:  # noqa: BLE001 - exhausted retries => defined error terminus
            run.outcome = "error"
            run.error = f"model act failed: {type(exc).__name__}: {exc}"
            if on_turn is not None:
                on_turn(run)
            break
        if action.done:
            run.outcome = "done"
            break

        results: list[ToolResult] = []
        for call in action.tool_calls:
            body = _body(call)

            # Safety gate (campaign/autonomous mode): never auto-run a state-changing action.
            # Hold it for the operator to approve instead. Recorded *before* the guardrail and
            # anti-loop checks so a held call is not counted as a failure or a dead end — it
            # stays approvable and re-proposable.
            if hold_mutating and _is_mutating(registry, call.name, call.arguments):
                if on_hold is not None:
                    on_hold(call, action.reasoning)
                results.append(
                    ToolResult(
                        call_id=call.id,
                        log=f"held for manual approval ({call.name} {body})",
                        ok=False,
                    )
                )
                continue

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
                _record_finding(findings, run, config, i, call, ctx, verifier)
            if assets is not None and call.name == "record_asset" and result.ok:
                _record_assets(assets, config, i, call)

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
        # Log-driven planning must see the fresh turn, but the plan call has to respect the same
        # context budget as `act` — otherwise a long run feeds plan() the full un-fitted
        # transcript and overflows the window. Re-fit the (now longer) transcript for the plan.
        try:
            if budget is not None:
                plan_fitted = _fit(run.transcript)
                run.compaction_reports.append(plan_fitted.report)
                plan_system = with_plan(
                    with_memory(plan_fitted.system, plan_fitted.memory), last_plan
                )
                turn.next_plan = _with_retry(
                    lambda ps=plan_system, pf=plan_fitted: backend.plan(
                        ps, pf.transcript, config
                    )
                )
            else:
                turn.next_plan = _with_retry(
                    lambda cs=call_system: backend.plan(cs, run.transcript, config)
                )
        except Exception as exc:  # noqa: BLE001 - exhausted retries => defined error terminus
            run.outcome = "error"
            run.error = f"model plan failed: {type(exc).__name__}: {exc}"
            if on_turn is not None:
                on_turn(run)
            break

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
