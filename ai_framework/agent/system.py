"""Builds the system message for a run: role, safety, skills, and tool schemas."""

from __future__ import annotations

import json
from typing import Any

from ai_framework.agent.contracts import MemoryRecord, RunConfig


def render_memory_block(records: list[MemoryRecord]) -> str:
    """Render recalled memory for injection into the system prompt (Step 5).

    Returns "" when there is nothing to recall, so callers can append unconditionally.
    """
    if not records:
        return ""
    lines = [f"- [{r.kind}] {r.technique or 'general'}: {r.body}" for r in records]
    return (
        "Relevant memory recalled from prior steps/sessions "
        "(use it; do not repeat known dead ends):\n" + "\n".join(lines)
    )


def with_memory(system: str, records: list[MemoryRecord]) -> str:
    """Append the recalled-memory block to a system prompt if there is any."""
    block = render_memory_block(records)
    return f"{system}\n\n{block}" if block else system


def with_plan(system: str, plan: str) -> str:
    """Fold the previous turn's log-driven plan into the system prompt.

    This is what makes planning *drive* the next action instead of being a discarded
    side-note: the plan the model produced from the last turn's logs steers this turn's
    ``act`` call. Returns ``system`` unchanged when there is no plan yet.
    """
    plan = plan.strip()
    if not plan:
        return system
    return f"{system}\n\nYour plan from the last turn's logs (execute the next step of it):\n{plan}"


def build_system_prompt(config: RunConfig, tools: list[dict[str, Any]]) -> str:
    authorized = ", ".join(sorted(config.authorized_targets)) or "(localhost only)"
    tool_lines = "\n".join(f"- {t['name']}: {t['description']}" for t in tools)
    return (
        "You are SecForge — a seasoned offensive-security researcher running an AUTHORIZED "
        "engagement. Think like a sharp human pentester, not a checklist: form hypotheses, "
        "reason from the evidence in the logs, stay curious, and adapt when the target "
        "surprises you. Be concise and direct, and say WHY a step matters — skip boilerplate "
        "and canned disclaimers.\n\n"
        "Method (the Hermes loop): read the latest logs, pick the single most informative next "
        "action, take it with a tool, then re-plan from what you learned. Favour the cheapest "
        "test that confirms or kills a hypothesis. Record real findings precisely; don't invent "
        "results you haven't observed.\n\n"
        "OPSEC & stealth: operate like a real adversary under observation. Prefer the "
        "least-noisy action that still proves the point; blend with legitimate traffic and "
        "living-off-the-land tooling rather than dropping obvious artifacts; remember a static "
        "source IP, a default TLS fingerprint, or a perfectly regular beacon is an attribution "
        "handle (a fresh IP is the cheapest, weakest change you can make). CRITICAL — document, "
        "don't destroy: keep a precise log of every action for the client; never delete their "
        "logs, corrupt data, or perform destructive anti-forensics. Tradecraft + the blue-team "
        "detection counterpart live in docs/RED_TEAM_OPSEC.md.\n\n"
        "Hard rule — authorization: act ONLY against the authorized targets below. If a "
        "promising lead is out of scope, note it and stop — never touch it.\n\n"
        f"Goal: {config.goal}\n"
        f"Target: {config.target}\n"
        f"Authorized targets: {authorized}\n\n"
        "Available tools:\n"
        f"{tool_lines}\n\n"
        f"Tool schemas:\n{json.dumps(tools, indent=2)}"
    )
