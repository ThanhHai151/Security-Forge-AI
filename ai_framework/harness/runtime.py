"""Runtime enforcement adapter for the operator-owned Rules of Engagement.

The harness policy is also rendered into an external coding agent's instructions.  That is
useful, but instructions alone must not be the only control.  This adapter classifies a
SecForge tool call, evaluates it against the immutable Rules of Engagement (RoE), and either
allows it, requires a specific operator approval token, or rejects it before the tool runs.

It deliberately contains no network or provider logic.  ``ToolRegistry`` calls it immediately
before execution, which makes it suitable for the explicitly enabled legacy autonomous engine
and for any future worker that uses the same registry.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ai_framework.harness.contracts import (
    ActionClass,
    ActionDisposition,
    ActionRequest,
    PolicyDecision,
    RulesOfEngagement,
)
from ai_framework.harness.policy import evaluate_action

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_PASSIVE_RECON_TOOLS = {"subfinder", "dnsx"}
_VULN_IDENTIFICATION_TOOLS = {"nuclei", "nikto", "ffuf", "gobuster", "sqlmap"}


class ToolPolicyError(PermissionError):
    """A tool call was outside the active Rules of Engagement.

    ``decision`` is retained for an API/UI layer to render a clear reason rather than trying to
    parse an exception string.  ``approval_token`` is populated only for actions that may proceed
    after an operator has approved this exact action in this exact RoE revision.
    """

    def __init__(self, decision: PolicyDecision, approval_token: str = "") -> None:
        self.decision = decision
        self.approval_token = approval_token
        reasons = "; ".join(decision.reasons)
        if decision.disposition == ActionDisposition.require_approval:
            message = f"operator approval required: {reasons}"
            if approval_token:
                message += f" (approval token: {approval_token})"
        else:
            message = f"blocked by Rules of Engagement: {reasons}"
        super().__init__(message)


def _text(value: object) -> str:
    return str(value or "").strip()


def _target_for_call(call: Any, primary_target: str) -> str:
    """Extract the target from a tool schema, falling back to the run's primary target."""
    args = getattr(call, "arguments", {}) or {}
    for key in ("url", "target", "csrf_url"):
        target = _text(args.get(key))
        if target:
            return target
    return primary_target


def action_request_for_tool(call: Any, tool: Any, primary_target: str = "") -> ActionRequest:
    """Map one registered tool invocation to a conservative RoE action class.

    Unknown networked tools default to active enumeration and unknown mutating tools default to
    state change.  This prevents a newly added tool from silently bypassing the control plane.
    """
    name = _text(getattr(call, "name", ""))
    args = getattr(call, "arguments", {}) or {}
    target = _target_for_call(call, primary_target)

    if name in {"note_finding", "record_asset"}:
        action = ActionClass.evidence_capture
    elif name in {"load_skill", "decode_encode", "jwt_attack"}:
        action = ActionClass.local_analysis
        target = ""
    elif name in {"http_get", "inspect_headers", "fetch_robots_sitemap"}:
        action = ActionClass.passive_reconnaissance
    elif name == "browser_render":
        # A headless browser executes page JavaScript and pulls subresources, so it is active
        # enumeration (medium risk, approval-gated on production/critical assets), NOT passive
        # recon — see ARCHITECTURE.md. Its own route gate additionally blocks non-GET subrequests.
        action = ActionClass.active_enumeration
    elif name == "http_request":
        method = _text(args.get("method") or "GET").upper()
        headers = args.get("headers") or {}
        body = _text(args.get("body"))
        action = (
            ActionClass.passive_reconnaissance
            if method in _SAFE_METHODS and not headers and not body
            else ActionClass.vulnerability_identification
            if method in _SAFE_METHODS
            else ActionClass.state_change
        )
    elif name == "run_recon":
        preset = _text(args.get("tool")).lower()
        if preset in _PASSIVE_RECON_TOOLS:
            action = ActionClass.passive_reconnaissance
        elif preset in _VULN_IDENTIFICATION_TOOLS:
            action = ActionClass.vulnerability_identification
        else:
            action = ActionClass.active_enumeration
    elif name in {"login", "set_auth"}:
        action = ActionClass.credential_use
    elif bool(getattr(tool, "mutating", False)):
        action = ActionClass.state_change
    elif bool(getattr(tool, "touches_network", False)):
        action = ActionClass.active_enumeration
    else:
        action = ActionClass.local_analysis
        target = ""

    return ActionRequest(
        action_class=action,
        target=target,
        summary=f"{name} tool call",
        reversible=action not in {ActionClass.state_change, ActionClass.credential_use},
    )


def approval_token_for_call(call: Any, decision: PolicyDecision) -> str:
    """Return a stable approval token bound to the action, arguments, and RoE digest.

    Approval for one endpoint, payload, or RoE revision cannot be replayed for another.  The token
    is intentionally an identifier rather than a secret; authentication and audit ownership stay
    with the calling UI/service.
    """
    payload = {
        "scope_digest": decision.scope_digest,
        "action_class": decision.action_class.value,
        "target": decision.target,
        "tool": _text(getattr(call, "name", "")),
        "arguments": getattr(call, "arguments", {}) or {},
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "roe-" + hashlib.sha256(encoded.encode()).hexdigest()[:24]


def enforce_tool_policy(call: Any, tool: Any, ctx: Any) -> PolicyDecision | None:
    """Fail closed when a tool invocation conflicts with the current RoE.

    Set ``ToolContext.approved_action_tokens`` to the token surfaced in ``ToolPolicyError`` after
    a human approval workflow has approved that exact action.  Calls without an RoE keep the
    existing scope gate behaviour for backwards compatibility.
    """
    roe = getattr(ctx, "rules_of_engagement", None)
    if not isinstance(roe, RulesOfEngagement):
        return None

    primary_target = _text(getattr(ctx, "primary_target", ""))
    request = action_request_for_tool(call, tool, primary_target)
    decision = evaluate_action(roe, request, primary_target=primary_target)
    if decision.disposition == ActionDisposition.allow:
        return decision

    token = approval_token_for_call(call, decision)
    approvals = set(getattr(ctx, "approved_action_tokens", set()) or set())
    if decision.disposition == ActionDisposition.require_approval and token in approvals:
        return decision
    raise ToolPolicyError(
        decision,
        approval_token=token if decision.disposition == ActionDisposition.require_approval else "",
    )
