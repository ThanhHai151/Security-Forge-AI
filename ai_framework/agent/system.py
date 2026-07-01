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


# A compact Red-Team OPSEC / no-destroy stanza pre-loaded into every campaign phase, so the
# stealth-and-don't-break-things discipline is always in context (full tradecraft:
# docs/RED_TEAM_OPSEC.md). This is the "skill installed by default" the brief calls for.
CAMPAIGN_OPSEC_SKILL = (
    "Loaded skill — Red-Team OPSEC (Stealth & Evasion): operate silently. Prefer the "
    "least-noisy read-only action that advances the engagement; avoid scan bursts and a "
    "perfectly regular cadence (both are attribution handles). NEVER run a state-changing or "
    "destructive action (POST/PUT/DELETE, writes, deletes, payloads that alter or corrupt data "
    "or structure) on your own — if such a test is warranted, PROPOSE it and let the operator "
    "approve it. Document every step; never destroy evidence or data."
)


def campaign_context_block(phase: int, untried: list[str], carry_over: str) -> str:
    """Build the campaign-continuity addon appended to a phase's system prompt.

    Pre-loads the OPSEC skill, tells the model which phase it is on, lists the *untried* leads
    to pursue (so it goes wider), and hands it the carry-over plan (so it goes deeper) — while
    reminding it not to repeat what earlier phases already covered.
    """
    lines = [CAMPAIGN_OPSEC_SKILL, "", f"Campaign phase: {phase}."]
    if carry_over.strip():
        lines.append(
            "Carry-over plan from the previous phase (continue it, going deeper on confirmed "
            f"leads):\n{carry_over.strip()}"
        )
    if untried:
        lines.append(
            "Untried leads to explore this phase (go wider — do NOT repeat techniques already "
            "tried in earlier phases; persistent memory lists those):\n- "
            + "\n- ".join(untried)
        )
    lines.append(
        "If neither the target nor these leads yield anything new, say so plainly in your plan "
        "so the engagement can conclude the target is well-defended."
    )
    return "\n".join(lines)


def with_campaign_context(system: str, phase: int, untried: list[str], carry_over: str) -> str:
    """Append the campaign-continuity block to a base system prompt."""
    return f"{system}\n\n{campaign_context_block(phase, untried, carry_over)}"


def _skill_catalog_block(tools: list[dict[str, Any]]) -> str:
    """Compact 'available skills' catalog, injected only when the ``load_skill`` tool is present.

    Progressive disclosure: the model sees each skill's name + when-to-use trigger and pulls the
    full procedure with ``load_skill`` when a trigger matches. Degrades to "" if the skills
    directory is missing or unreadable, so the prompt never breaks.
    """
    if not any(t.get("name") == "load_skill" for t in tools):
        return ""
    try:
        from ai_framework.skills.loader import SkillRegistry

        catalog = SkillRegistry().catalog()
    except Exception:  # noqa: BLE001 - skills are optional; never break prompt assembly
        return ""
    if not catalog:
        return ""
    lines = "\n".join(f"- {s['name']}: {s['trigger']}" for s in catalog)
    return (
        "\n\nAvailable skills (on-demand knowledge — call load_skill with the name when a "
        "trigger matches what you're seeing):\n" + lines
    )


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
        "handle (a fresh IP is the cheapest, weakest change you can make — durable evasion is "
        "reshaping tool/behaviour fingerprints, not rotating IPs or timezones). Detection has "
        "moved up-stack: identity and cloud (OAuth/token replay, Kerberos tickets, cloud-log "
        "tampering) and endpoint telemetry (EDR/ETW/AMSI) are watched as closely as the network. "
        "CRITICAL — document, don't destroy: keep a precise log of every action for the client; "
        "never delete their logs, corrupt data, or perform destructive anti-forensics. Tradecraft "
        "+ the blue-team detection counterpart live in docs/RED_TEAM_OPSEC.md.\n\n"
        "Hard rule — authorization: act ONLY against the authorized targets below. If a "
        "promising lead is out of scope, note it and stop — never touch it.\n\n"
        f"Goal: {config.goal}\n"
        f"Target: {config.target}\n"
        f"Authorized targets: {authorized}\n\n"
        "Available tools:\n"
        f"{tool_lines}"
        f"{_skill_catalog_block(tools)}\n\n"
        f"Tool schemas:\n{json.dumps(tools, indent=2)}"
    )
