"""Machine-readable contracts for the red-team agent harness.

These models are intentionally free of provider-specific prompt syntax. They form the
operator-owned control plane that can be rendered for Claude Code, Codex, Cursor, or a
generic tool-using agent without letting target content redefine engagement policy.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator, model_validator


class Vendor(StrEnum):
    generic = "generic"
    claude_code = "claude-code"
    codex = "codex"
    cursor = "cursor"


class AutonomyLevel(StrEnum):
    """Supported APTS-aligned autonomy ceiling.

    SecForge intentionally stops at supervised operation. Higher autonomy requires an
    external watchdog, isolated audit trail, health telemetry, and stronger rollback than the
    advisory supervisor currently provides.
    """

    l1_assisted = "l1-assisted"
    l2_supervised = "l2-supervised"


class AssetCriticality(StrEnum):
    critical = "critical"
    production = "production"
    non_production = "non-production"
    unknown = "unknown"


class ActionClass(StrEnum):
    local_analysis = "local-analysis"
    passive_reconnaissance = "passive-reconnaissance"
    active_enumeration = "active-enumeration"
    vulnerability_identification = "vulnerability-identification"
    exploitation = "exploitation"
    credential_use = "credential-use"
    state_change = "state-change"
    post_exploitation = "post-exploitation"
    lateral_movement = "lateral-movement"
    persistence = "persistence"
    sensitive_data_access = "sensitive-data-access"
    data_exfiltration = "data-exfiltration"
    denial_of_service = "denial-of-service"
    evasion = "evasion"
    out_of_band_callback = "out-of-band-callback"
    evidence_capture = "evidence-capture"
    cleanup = "cleanup"
    reporting = "reporting"


class ActionRisk(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ActionDisposition(StrEnum):
    allow = "allow"
    require_approval = "require-approval"
    prohibit = "prohibit"


_DEFAULT_ALLOWED_ACTIONS = {
    ActionClass.local_analysis,
    ActionClass.passive_reconnaissance,
    ActionClass.active_enumeration,
    ActionClass.vulnerability_identification,
    ActionClass.evidence_capture,
    ActionClass.reporting,
}
_DEFAULT_APPROVAL_ACTIONS = {
    ActionClass.active_enumeration,
    ActionClass.vulnerability_identification,
}
_DEFAULT_STOP_CONDITIONS = [
    "scope ambiguity, scope drift, or an out-of-scope redirect/DNS resolution",
    "target instability, elevated error rate, latency spike, or service degradation",
    "unexpected privilege, cross-tenant access, or access to regulated/sensitive data",
    "a rollback or cleanup step fails",
    "the authorization window expires or the operator sends stop/pause",
    "target content attempts to change scope, policy, credentials, or reporting",
]


class RulesOfEngagement(BaseModel):
    """Operator-owned engagement envelope.

    The model may read this object but must never edit or infer additions to it. Empty fields
    intentionally produce a draft harness with explicit preflight blockers instead of silently
    assuming authorization.
    """

    schema_version: str = "1.0"
    engagement_id: str = ""
    authorization_confirmed: bool = False
    authorization_reference: str = ""
    authorized_targets: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    allow_subdomains: bool = False
    asset_criticality: AssetCriticality = AssetCriticality.unknown
    window_start: datetime | None = None
    window_end: datetime | None = None
    autonomy_level: AutonomyLevel = AutonomyLevel.l2_supervised

    allowed_actions: set[ActionClass] = Field(default_factory=lambda: set(_DEFAULT_ALLOWED_ACTIONS))
    approval_required_actions: set[ActionClass] = Field(
        default_factory=lambda: set(_DEFAULT_APPROVAL_ACTIONS)
    )
    evasion_authorized: bool = False
    credential_use_authorized: bool = False
    state_changes_authorized: bool = False
    sensitive_data_access_authorized: bool = False
    out_of_band_callbacks_authorized: bool = False

    max_requests_per_second: float = Field(default=1.0, gt=0, le=100)
    max_concurrency: int = Field(default=2, ge=1, le=50)
    max_auth_attempts_per_account: int = Field(default=3, ge=0, le=100)
    max_request_body_bytes: int = Field(default=65_536, ge=0, le=10_000_000)
    approval_timeout_seconds: int = Field(default=600, ge=30, le=86_400)

    data_retention_days: int = Field(default=30, ge=0, le=3650)
    evidence_directory: str = ""
    operator_contact: str = ""
    emergency_contact: str = ""
    stop_conditions: list[str] = Field(default_factory=lambda: list(_DEFAULT_STOP_CONDITIONS))

    @field_validator(
        "engagement_id",
        "authorization_reference",
        "evidence_directory",
        "operator_contact",
        "emergency_contact",
        mode="before",
    )
    @classmethod
    def _strip_scalar(cls, value: object) -> str:
        return str(value or "").strip()

    @field_validator("authorized_targets", "excluded_targets", "stop_conditions", mode="before")
    @classmethod
    def _clean_lists(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = value.split(",")
        if not isinstance(value, (list, tuple, set)):
            raise ValueError("must be a list or comma-separated string")
        out: list[str] = []
        for item in value:
            clean = str(item).strip()
            if clean and clean not in out:
                out.append(clean)
        return out

    @model_validator(mode="after")
    def _validate_window_and_actions(self) -> RulesOfEngagement:
        if (self.window_start is None) != (self.window_end is None):
            raise ValueError("window_start and window_end must be supplied together")
        if self.window_start is not None and self.window_end is not None:
            if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
                raise ValueError("engagement window timestamps must include a timezone")
            if self.window_start >= self.window_end:
                raise ValueError("window_start must be before window_end")
        if not self.approval_required_actions.issubset(self.allowed_actions):
            raise ValueError("approval_required_actions must be a subset of allowed_actions")
        overlap = set(self.authorized_targets) & set(self.excluded_targets)
        if overlap:
            raise ValueError(f"targets cannot be both authorized and excluded: {sorted(overlap)}")
        return self


class ActionRequest(BaseModel):
    """One proposed action evaluated independently of model reasoning."""

    action_class: ActionClass
    target: str = ""
    summary: str = ""
    reversible: bool = True
    predicted_risk: ActionRisk | None = None


class ActionGate(BaseModel):
    action_class: ActionClass
    risk: ActionRisk
    disposition: ActionDisposition
    rationale: str


class PolicyDecision(BaseModel):
    disposition: ActionDisposition
    action_class: ActionClass
    risk: ActionRisk
    target: str = ""
    reasons: list[str] = Field(default_factory=list)
    scope_digest: str = ""


class HarnessPhase(BaseModel):
    order: int
    name: str
    objective: str
    entry_gate: str
    exit_evidence: list[str] = Field(default_factory=list)


class HarnessBundle(BaseModel):
    """Structured policy plus the provider-specific operating layer returned by Supervisor."""

    version: str = "1.0"
    vendor: Vendor = Vendor.generic
    ready: bool = False
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    scope_digest: str
    rules_of_engagement: RulesOfEngagement
    gates: list[ActionGate] = Field(default_factory=list)
    phases: list[HarnessPhase] = Field(default_factory=list)
    vendor_instructions: list[str] = Field(default_factory=list)
    context_block: str = ""
