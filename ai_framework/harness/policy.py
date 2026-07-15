"""Deterministic scope and action policy for the red-team harness.

Nothing in this module calls a model or a target. It is suitable for a pre-tool hook or
control-plane check because decisions are derived exclusively from operator-owned RoE data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from urllib.parse import urlparse

from ai_framework.harness.contracts import (
    ActionClass,
    ActionDisposition,
    ActionGate,
    ActionRequest,
    ActionRisk,
    AssetCriticality,
    AutonomyLevel,
    HarnessBundle,
    HarnessPhase,
    PolicyDecision,
    RulesOfEngagement,
    Vendor,
)
from ai_framework.harness.render import render_harness_context, vendor_instructions

_LOCAL_ACTIONS = {
    ActionClass.local_analysis,
    ActionClass.evidence_capture,
    ActionClass.reporting,
}
_NETWORK_ACTIONS = set(ActionClass) - _LOCAL_ACTIONS
_ALWAYS_PROHIBITED = {
    ActionClass.persistence,
    ActionClass.data_exfiltration,
    ActionClass.denial_of_service,
}
_ALWAYS_APPROVAL = {
    ActionClass.exploitation,
    ActionClass.credential_use,
    ActionClass.state_change,
    ActionClass.post_exploitation,
    ActionClass.lateral_movement,
    ActionClass.sensitive_data_access,
    ActionClass.evasion,
    ActionClass.out_of_band_callback,
    ActionClass.cleanup,
}
_ACTION_RISK: dict[ActionClass, ActionRisk] = {
    ActionClass.local_analysis: ActionRisk.low,
    ActionClass.passive_reconnaissance: ActionRisk.low,
    ActionClass.active_enumeration: ActionRisk.medium,
    ActionClass.vulnerability_identification: ActionRisk.medium,
    ActionClass.exploitation: ActionRisk.high,
    ActionClass.credential_use: ActionRisk.high,
    ActionClass.state_change: ActionRisk.high,
    ActionClass.post_exploitation: ActionRisk.high,
    ActionClass.lateral_movement: ActionRisk.critical,
    ActionClass.persistence: ActionRisk.critical,
    ActionClass.sensitive_data_access: ActionRisk.critical,
    ActionClass.data_exfiltration: ActionRisk.critical,
    ActionClass.denial_of_service: ActionRisk.critical,
    ActionClass.evasion: ActionRisk.high,
    ActionClass.out_of_band_callback: ActionRisk.high,
    ActionClass.evidence_capture: ActionRisk.low,
    ActionClass.cleanup: ActionRisk.medium,
    ActionClass.reporting: ActionRisk.low,
}
_HARD_DENIED_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
    "fd00:ec2::254",
}


def _canonicalize(value: object) -> object:
    """Turn RoE data into a stable JSON shape, including unordered action sets."""
    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in sorted(value.items())}
    if isinstance(value, set):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    enum_value = getattr(value, "value", None)
    return enum_value if isinstance(enum_value, str) else value


def scope_digest(roe: RulesOfEngagement) -> str:
    canonical = _canonicalize(roe.model_dump(mode="python"))
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _host(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    if "://" in raw:
        return (urlparse(raw).hostname or "").lower().rstrip(".")
    candidate = raw[2:] if raw.startswith("*.") else raw
    unbracketed = (
        candidate[1:-1] if candidate.startswith("[") and candidate.endswith("]") else candidate
    )
    try:
        return ipaddress.ip_address(unbracketed).compressed.lower()
    except ValueError:
        pass
    # urlparse only recognizes a port reliably with a leading //.
    parsed = urlparse("//" + candidate)
    return (parsed.hostname or candidate).lower().rstrip(".")


def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    raw = value.strip()
    if "://" in raw or raw.startswith("*."):
        return None
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None


def _is_hard_denied(value: str) -> bool:
    from ai_framework.harness.netguard import normalize_host

    host = _host(value)
    if host in _HARD_DENIED_HOSTS:
        return True
    # Canonicalize encoded literals (integer/hex/IPv4-mapped-IPv6) so an obfuscated
    # metadata/link-local address cannot dodge the deny check. Loopback and private ranges are
    # NOT hard-denied here (a local lab / staging host is a legitimate authorized target); those
    # are gated at the egress guard, which honours RoE.allow_private_ranges.
    canonical = normalize_host(host)
    if canonical in _HARD_DENIED_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(canonical)
    except ValueError:
        return False
    return ip.is_link_local or ip.is_multicast or ip.is_unspecified


def _entry_matches(candidate: str, entry: str, allow_subdomains: bool) -> bool:
    candidate_host = _host(candidate)
    net = _network(entry)
    if net is not None:
        try:
            return ipaddress.ip_address(candidate_host) in net
        except ValueError:
            return False
    entry_host = _host(entry)
    if not candidate_host or not entry_host:
        return False
    if candidate_host == entry_host:
        return True
    wildcard = entry.strip().startswith("*.")
    return (wildcard or allow_subdomains) and candidate_host.endswith("." + entry_host)


def target_is_in_scope(target: str, roe: RulesOfEngagement) -> bool:
    """Deny wins; a bare authorized domain only includes children when explicitly enabled."""
    if not target or _is_hard_denied(target):
        return False
    if any(_entry_matches(target, item, True) for item in roe.excluded_targets):
        return False
    return any(
        _entry_matches(target, item, roe.allow_subdomains) for item in roe.authorized_targets
    )


def preflight_blockers(
    roe: RulesOfEngagement,
    primary_target: str = "",
    now: datetime | None = None,
) -> list[str]:
    now = now or datetime.now(UTC)
    blockers: list[str] = []
    if not roe.authorization_confirmed:
        blockers.append("written authorization has not been explicitly confirmed")
    if not roe.authorization_reference:
        blockers.append("authorization_reference is missing")
    if not roe.authorized_targets:
        blockers.append("authorized_targets is empty")
    if any(_is_hard_denied(item) for item in roe.authorized_targets):
        blockers.append("authorized_targets contains a hard-denied metadata/link-local address")
    if primary_target and roe.authorized_targets and not target_is_in_scope(primary_target, roe):
        blockers.append("the requested target is not inside the authorized target set")
    if roe.window_start is None or roe.window_end is None:
        blockers.append("an explicit timezone-aware testing window is missing")
    elif not (roe.window_start <= now <= roe.window_end):
        blockers.append("the current time is outside the authorized testing window")
    return blockers


def _gate_for(action: ActionClass, roe: RulesOfEngagement) -> ActionGate:
    risk = _ACTION_RISK[action]
    if action in _ALWAYS_PROHIBITED:
        return ActionGate(
            action_class=action,
            risk=risk,
            disposition=ActionDisposition.prohibit,
            rationale="hard-prohibited by the SecForge harness regardless of model request",
        )
    if action not in roe.allowed_actions:
        return ActionGate(
            action_class=action,
            risk=risk,
            disposition=ActionDisposition.prohibit,
            rationale="not present in the operator-owned allowed_actions set",
        )

    feature_authorized = {
        ActionClass.evasion: roe.evasion_authorized,
        ActionClass.credential_use: roe.credential_use_authorized,
        ActionClass.state_change: roe.state_changes_authorized,
        ActionClass.sensitive_data_access: roe.sensitive_data_access_authorized,
        ActionClass.out_of_band_callback: roe.out_of_band_callbacks_authorized,
    }
    if action in feature_authorized and not feature_authorized[action]:
        return ActionGate(
            action_class=action,
            risk=risk,
            disposition=ActionDisposition.prohibit,
            rationale=f"{action.value} needs an explicit RoE authorization flag",
        )

    approval = action in roe.approval_required_actions or action in _ALWAYS_APPROVAL
    if roe.autonomy_level == AutonomyLevel.l1_assisted and action in _NETWORK_ACTIONS:
        approval = True
    if roe.asset_criticality in {
        AssetCriticality.critical,
        AssetCriticality.production,
        AssetCriticality.unknown,
    } and action in {ActionClass.active_enumeration, ActionClass.vulnerability_identification}:
        approval = True
    return ActionGate(
        action_class=action,
        risk=risk,
        disposition=(ActionDisposition.require_approval if approval else ActionDisposition.allow),
        rationale=(
            "operator approval is required before this action"
            if approval
            else "allowed within the validated scope, window, and rate limits"
        ),
    )


def action_gates(roe: RulesOfEngagement, preflight_ready: bool = True) -> list[ActionGate]:
    gates = [_gate_for(action, roe) for action in ActionClass]
    if preflight_ready:
        return gates
    return [
        gate.model_copy(
            update={
                "disposition": ActionDisposition.prohibit,
                "rationale": "network actions are blocked until RoE preflight is ready",
            }
        )
        if gate.action_class in _NETWORK_ACTIONS
        else gate
        for gate in gates
    ]


def evaluate_action(
    roe: RulesOfEngagement,
    request: ActionRequest,
    primary_target: str = "",
    now: datetime | None = None,
) -> PolicyDecision:
    """Evaluate one proposed action. Any ambiguity fails closed."""
    digest = scope_digest(roe)
    gate = _gate_for(request.action_class, roe)
    reasons: list[str] = []
    disposition = gate.disposition

    if request.action_class in _NETWORK_ACTIONS:
        blockers = preflight_blockers(roe, primary_target=primary_target, now=now)
        if blockers:
            disposition = ActionDisposition.prohibit
            reasons.extend(blockers)
        if not request.target:
            disposition = ActionDisposition.prohibit
            reasons.append("network action has no explicit target")
        elif not target_is_in_scope(request.target, roe):
            disposition = ActionDisposition.prohibit
            reasons.append("action target is excluded, hard-denied, or outside scope")
    if not request.reversible and disposition == ActionDisposition.allow:
        disposition = ActionDisposition.require_approval
        reasons.append("the proposed action is not demonstrably reversible")
    if request.predicted_risk in {ActionRisk.high, ActionRisk.critical}:
        if disposition == ActionDisposition.allow:
            disposition = ActionDisposition.require_approval
        reasons.append("caller classified the action as high/critical impact")
    if not reasons:
        reasons.append(gate.rationale)

    return PolicyDecision(
        disposition=disposition,
        action_class=request.action_class,
        risk=request.predicted_risk or gate.risk,
        target=request.target,
        reasons=reasons,
        scope_digest=digest,
    )


def _phases() -> list[HarnessPhase]:
    return [
        HarnessPhase(
            order=0,
            name="Initialization",
            objective=(
                "Validate authorization, scope, exclusions, window, criticality, limits, "
                "and stop contacts without touching the target."
            ),
            entry_gate=(
                "No target traffic. Resolve every preflight blocker and freeze the RoE digest."
            ),
            exit_evidence=["operator authorization", "scope digest", "active test window"],
        ),
        HarnessPhase(
            order=1,
            name="Reconnaissance",
            objective=(
                "Build a low-noise external picture and threat model before selecting tests."
            ),
            entry_gate=(
                "Preflight ready; passive actions first; active requests follow their action gate."
            ),
            exit_evidence=["asset inventory", "technology hypotheses", "trust boundaries"],
        ),
        HarnessPhase(
            order=2,
            name="Enumeration",
            objective=(
                "Map reachable routes, parameters, identities, roles, state transitions, "
                "and business invariants."
            ),
            entry_gate="Stay inside the frozen target set and per-host request budget.",
            exit_evidence=["attack-surface graph", "role/session matrix", "input-to-sink map"],
        ),
        HarnessPhase(
            order=3,
            name="Identification",
            objective="Turn observations into ranked, falsifiable vulnerability hypotheses.",
            entry_gate=(
                "Every lead needs a baseline/control pair and an expected differentiating signal."
            ),
            exit_evidence=["hypothesis ledger", "controls", "candidate confidence"],
        ),
        HarnessPhase(
            order=4,
            name="Exploitation",
            objective=(
                "Validate the minimum security impact needed to prove or reject a candidate."
            ),
            entry_gate=(
                "Explicit action-gate approval; define rollback and stop conditions before "
                "execution."
            ),
            exit_evidence=["minimal reproducible proof", "raw request/response", "impact boundary"],
        ),
        HarnessPhase(
            order=5,
            name="Post-Exploitation",
            objective=(
                "Demonstrate only the pre-authorized objective; do not explore merely because "
                "access exists."
            ),
            entry_gate=(
                "Separately authorized in allowed_actions; no automatic chaining or new targets."
            ),
            exit_evidence=["objective proof", "access boundary", "artifact inventory"],
        ),
        HarnessPhase(
            order=6,
            name="Cleanup and Integrity",
            objective=(
                "Preserve evidence, reverse approved changes, remove test artifacts, and "
                "verify target health."
            ),
            entry_gate=(
                "Use the recorded pre-state and rollback procedure; halt on any cleanup mismatch."
            ),
            exit_evidence=["rollback result", "artifact reconciliation", "health check"],
        ),
        HarnessPhase(
            order=7,
            name="Reporting",
            objective=(
                "Report verified findings, unverified leads, negatives, blocked tests, and "
                "residual coverage gaps separately."
            ),
            entry_gate=(
                "Reconcile claims against raw evidence and the complete action/decision log."
            ),
            exit_evidence=["finding provenance", "coverage matrix", "human review queue"],
        ),
    ]


def build_harness(
    primary_target: str,
    roe: RulesOfEngagement | None = None,
    vendor: Vendor = Vendor.generic,
    scan_mode: str = "standard",
    assessment_mode: str = "blackbox",
    now: datetime | None = None,
) -> HarnessBundle:
    """Build a complete structured + rendered harness without mutating caller-owned RoE."""
    source = roe or RulesOfEngagement()
    if not source.authorized_targets and primary_target:
        source = source.model_copy(update={"authorized_targets": [primary_target]})
    blockers = preflight_blockers(source, primary_target=primary_target, now=now)
    warnings: list[str] = []
    if source.asset_criticality == AssetCriticality.unknown:
        warnings.append("asset criticality is unknown and is treated as production")
    if not source.emergency_contact:
        warnings.append("no emergency contact supplied; any safety trigger must fail closed")
    if not source.evidence_directory:
        warnings.append(
            "no external evidence directory supplied; preserve raw output outside target data"
        )
    if source.evasion_authorized:
        warnings.append("evasion is enabled and must be disclosed in the final report")

    bundle = HarnessBundle(
        vendor=vendor,
        ready=not blockers,
        blockers=blockers,
        warnings=warnings,
        scope_digest=scope_digest(source),
        rules_of_engagement=source,
        gates=action_gates(source, preflight_ready=not blockers),
        phases=_phases(),
        vendor_instructions=vendor_instructions(vendor),
    )
    bundle.context_block = render_harness_context(
        bundle,
        primary_target=primary_target,
        scan_mode=scan_mode,
        assessment_mode=assessment_mode,
    )
    return bundle
