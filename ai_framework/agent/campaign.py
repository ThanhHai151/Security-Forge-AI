"""Campaign layer — a continuous ("infinite") engagement chained from bounded phases.

A single ``run_loop`` is one bounded run: it observes, reasons, acts, and plans for
``step_budget`` turns, then stops. A **campaign** chains those runs into one long engagement
against a domain. Each **phase** is a ``run_loop`` that inherits everything the prior phases
learned (persistent per-target memory already suppresses repeats), carries the last plan
forward, and pushes coverage deeper + wider. Between phases the campaign pauses
(``awaiting_user``) so the operator decides whether to continue — matching the brief's
"ask each time" model — and records ``no_new_findings_within_budget`` when consecutive phases
stop producing new evidence. That outcome never claims the target is hardened or secure.

Design borrowed from CAI's continuous-ops: a task/coverage list that marks what was tried vs.
untried so plans never repeat old work (``task_queue.py``), a rolling carry-over summary
(``tick_context.py``), and a "keep going?" stop signal (``continuation.py``). No new engine —
this orchestrates the existing loop; see ``backend/service.py``.

Safety: state-changing (``mutating``) tool calls are never auto-run inside a campaign. The loop
*holds* them (see ``loop.py`` ``hold_mutating``) as ``PendingApproval`` entries; only an
operator-approved single call ever executes. Stealth (OPSEC pacing) is on by default here.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from ai_framework.agent.contracts import Run, ToolCall
from ai_framework.harness.contracts import RulesOfEngagement
from ai_framework.security.redaction import redact_data


def _now() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return uuid4().hex


# A small vocabulary of web-attack techniques → keywords, so coverage stays meaningful even
# when tool names are generic (http_get, http_request). Leads mentioned in a plan but not yet
# exercised become "untried"; once a call/finding exercises one it flips to "tried". This is
# the tried/untried map the brief asks for, and what steers the next plan away from repeats.
TECHNIQUES: dict[str, tuple[str, ...]] = {
    "recon": ("recon", "reconnaissance", "fingerprint", "enumerate", "robots", "sitemap"),
    "sqli": ("sql injection", "sqli", "sqlmap", "union select", "' or 1=1", "boolean-based"),
    "xss": ("xss", "cross-site scripting", "<script", "onerror", "reflected", "stored xss"),
    "ssrf": ("ssrf", "server-side request forgery", "gopher://", "169.254.169.254", "metadata"),
    "idor": ("idor", "insecure direct object", "object reference", "increment the id"),
    "csrf": ("csrf", "cross-site request forgery", "anti-csrf", "samesite"),
    "xxe": ("xxe", "xml external entity", "<!entity", "doctype"),
    "ssti": ("ssti", "template injection", "{{7*7}}", "${", "jinja"),
    "lfi": ("lfi", "local file inclusion", "path traversal", "../", "directory traversal"),
    "open-redirect": ("open redirect", "open-redirect", "redirect_uri", "returnurl"),
    "cors": ("cors", "access-control-allow-origin", "cross-origin"),
    "auth": ("authentication", "auth bypass", "login", "brute force", "credential", "session"),
    "jwt": ("jwt", "json web token", "alg:none", "alg-none", "none algorithm", "kid header",
            "hs256", "jwt_attack", "forge-hs256", "crack-hs256"),
    "headers": ("security header", "hsts", "content-security-policy", "csp", "x-frame-options"),
    "host-header": ("host header", "host-header", "x-forwarded-host", "cache poisoning"),
    "file-upload": ("file upload", "upload a", "multipart", "content-type bypass"),
    "graphql": ("graphql", "introspection", "__schema"),
    "info-disclosure": ("information disclosure", "stack trace", "verbose error", "leaked"),
    # Signals from the external-tool runner and the operational skill set.
    "content-discovery": ("content discovery", "directory brute", "ffuf", "gobuster",
                          "dirbuster", "fuzz", "wordlist", "katana"),
    "vuln-scan": ("nuclei", "vulnerability scan", "nikto", "template scan", "wafw00f"),
    "command-injection": ("command injection", "os command", "rce", "remote code execution",
                          "; id", "| id", "$(", "`id`"),
    "deserialization": ("deserialization", "insecure deserialization", "pickle", "ysoserial",
                        "gadget chain", "__reduce__"),
    "nosql": ("nosql", "nosql injection", "$where", "$ne", "mongodb"),
}


class CoverageStatus(StrEnum):
    untried = "untried"      # a lead named in a plan, not yet exercised
    tried = "tried"          # exercised by a tool call (no confirmed impact)
    confirmed = "confirmed"  # exercised and produced a finding
    blocked = "blocked"      # a mutating action held for manual approval


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


class CampaignStatus(StrEnum):
    running = "running"            # a phase is executing
    awaiting_user = "awaiting_user"  # phase done; waiting for continue/stop
    no_new_findings = "no_new_findings_within_budget"
    hardened = "hardened"          # legacy persisted value; never emitted by new campaigns
    completed = "completed"        # autopilot ran its full phase budget and stopped on its own
    stopped = "stopped"            # operator ended it
    error = "error"


class CoverageItem(BaseModel):
    """One technique in the tried/untried map for a campaign's target."""

    id: str = Field(default_factory=_new_id)
    technique: str
    description: str = ""
    status: CoverageStatus = CoverageStatus.untried
    phase: int = 0
    last_run_at: datetime | None = None


class PendingApproval(BaseModel):
    """A state-changing tool call the loop held instead of auto-running (safety gate)."""

    id: str = Field(default_factory=_new_id)
    phase: int
    tool_call: ToolCall
    rationale: str = ""
    status: ApprovalStatus = ApprovalStatus.pending
    result_log: str = ""


class CampaignConfig(BaseModel):
    """Inputs that define a continuous engagement against one domain."""

    domain: str
    backend: str = "offline"
    model: str | None = None
    base_url: str | None = None
    authorized_targets: set[str] = Field(default_factory=set)
    rules_of_engagement: RulesOfEngagement | None = None
    phase_step_budget: int = 8
    # Autopilot: chain phases back-to-back with no operator pause, so a single request drives
    # the whole engagement to a stop condition. ``max_phases`` bounds it (budget + safety);
    # the campaign records no-new-findings or ``completed`` (budget spent)
    # on its own. ``auto_approve_mutating`` additionally lets state-changing actions run without
    # being held for approval — full independent execution, still behind the authorized-scope gate.
    autopilot: bool = False
    max_phases: int = 6
    auto_approve_mutating: bool = False
    # Stealth is ON by default for campaigns (the brief: "always pentest in silence").
    opsec_min_interval: float = 2.0
    opsec_jitter: float = 2.0

    def target_url(self) -> str:
        """The domain as an absolute http(s) URL the loop can fetch."""
        d = self.domain.strip()
        if d.startswith(("http://", "https://")):
            return d
        return f"http://{d}"

    def all_authorized(self) -> set[str]:
        """Authorized hosts: the caller's set plus the domain's own host (bare + www)."""
        from urllib.parse import urlparse

        host = urlparse(self.target_url()).hostname or self.domain.strip()
        extra = {host}
        if host.startswith("www."):
            extra.add(host[4:])
        return set(self.authorized_targets) | extra


class Campaign(BaseModel):
    """A continuous engagement: config + the chain of phase run-ids + live state."""

    id: str = Field(default_factory=_new_id)
    created_at: datetime = Field(default_factory=_now)
    config: CampaignConfig
    status: CampaignStatus = CampaignStatus.running
    phases: list[str] = Field(default_factory=list)  # Run ids, one per phase
    coverage: list[CoverageItem] = Field(default_factory=list)
    pending_approvals: list[PendingApproval] = Field(default_factory=list)
    carry_over_plan: str = ""
    hardened_streak: int = 0
    error: str = ""

    @property
    def phase_count(self) -> int:
        return len(self.phases)


# --- Coverage derivation ----------------------------------------------------


def _scan_techniques(text: str) -> set[str]:
    """Return the technique slugs whose keywords appear in ``text`` (case-insensitive)."""
    low = text.lower()
    hits: set[str] = set()
    for slug, keywords in TECHNIQUES.items():
        if any(kw in low for kw in keywords):
            hits.add(slug)
    return hits


def _held(log: str) -> bool:
    return "held for manual approval" in log.lower()


def derive_coverage(run: Run, prior: list[CoverageItem], phase: int) -> list[CoverageItem]:
    """Fold one phase's transcript into the running tried/untried map.

    * Techniques exercised by a tool call → ``tried`` (``confirmed`` if that turn also recorded
      a ``note_finding``). A held mutating call → ``blocked``.
    * Techniques only *named* in reasoning/plan text → ``untried`` (a lead to pursue next),
      unless already tried/confirmed.
    Prior items are preserved so the map accumulates across phases and never loses history.
    """
    items: dict[str, CoverageItem] = {c.technique: c for c in prior}

    def upsert(slug: str, status: CoverageStatus, detail: str) -> None:
        cur = items.get(slug)
        rank = {  # only ever escalate a technique's status, never downgrade it
            CoverageStatus.untried: 0,
            CoverageStatus.blocked: 1,
            CoverageStatus.tried: 2,
            CoverageStatus.confirmed: 3,
        }
        if cur is None:
            items[slug] = CoverageItem(
                technique=slug, description=detail, status=status, phase=phase, last_run_at=_now()
            )
            return
        if rank[status] >= rank[cur.status]:
            cur.status = status
            cur.phase = phase
            cur.last_run_at = _now()
            if detail:
                cur.description = detail

    exercised: set[str] = set()   # techniques touched by an actual call this phase
    confirmed: set[str] = set()   # techniques with a finding this phase
    blocked: set[str] = set()     # techniques held for approval this phase
    mentioned: set[str] = set()   # techniques merely named in reasoning/plans

    for turn in run.transcript:
        held_calls = {r.call_id for r in turn.tool_results if _held(r.log)}
        for call in turn.tool_calls:
            arg_text = json.dumps(call.arguments)
            slugs = _scan_techniques(f"{call.name} {arg_text}") or {"recon"}
            if call.id in held_calls:
                blocked |= slugs
            elif call.name == "note_finding":
                confirmed |= _scan_techniques(arg_text) or {"info-disclosure"}
            else:
                exercised |= slugs
        mentioned |= _scan_techniques(f"{turn.reasoning}\n{turn.next_plan}")

    for slug in exercised:
        upsert(slug, CoverageStatus.tried, "")
    for slug in blocked:
        upsert(slug, CoverageStatus.blocked, "state-changing action held for approval")
    for slug in confirmed:
        upsert(slug, CoverageStatus.confirmed, "produced a finding")
    for slug in mentioned - exercised - confirmed:
        if slug not in items or items[slug].status == CoverageStatus.untried:
            upsert(slug, CoverageStatus.untried, "lead identified in planning — not yet exercised")

    # Stable order: confirmed, blocked, tried, untried, then alphabetical.
    order = {
        CoverageStatus.confirmed: 0,
        CoverageStatus.blocked: 1,
        CoverageStatus.tried: 2,
        CoverageStatus.untried: 3,
    }
    return sorted(items.values(), key=lambda c: (order[c.status], c.technique))


def record_manual_action(
    coverage: list[CoverageItem], call: ToolCall, ok: bool, phase: int
) -> list[CoverageItem]:
    """Fold an operator-approved (previously held) action's result into the coverage map.

    A successful state-changing action is a ``confirmed`` impact; a failed one is ``tried``.
    """
    items = {c.technique: c for c in coverage}
    slugs = _scan_techniques(f"{call.name} {json.dumps(call.arguments)}") or {"recon"}
    status = CoverageStatus.confirmed if ok else CoverageStatus.tried
    for slug in slugs:
        cur = items.get(slug)
        if cur is None:
            items[slug] = CoverageItem(
                technique=slug, description="operator-approved action", status=status,
                phase=phase, last_run_at=_now(),
            )
        else:
            cur.status = status
            cur.phase = phase
            cur.last_run_at = _now()
    return list(items.values())


def coverage_signature(coverage: list[CoverageItem]) -> tuple[int, int]:
    """(confirmed count, untried count) — the pair that tells us if a phase made progress."""
    confirmed = sum(1 for c in coverage if c.status == CoverageStatus.confirmed)
    untried = sum(1 for c in coverage if c.status == CoverageStatus.untried)
    return confirmed, untried


def is_hardened(campaign: Campaign, threshold: int = 2) -> bool:
    """True when consecutive phases stopped surfacing anything new (target looks protected)."""
    return campaign.hardened_streak >= threshold


# --- Persistence (one JSON file per campaign, like JsonRunStore) ------------


class CampaignStore:
    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)

    def _path(self, campaign_id: str) -> Path:
        return self.dir / f"{campaign_id}.json"

    def save(self, campaign: Campaign) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self._path(campaign.id).with_suffix(".json.tmp")
        data = redact_data(campaign.model_dump(mode="json"))
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._path(campaign.id))

    def load(self, campaign_id: str) -> Campaign | None:
        path = self._path(campaign_id)
        if not path.is_file():
            return None
        return Campaign.model_validate_json(path.read_text(encoding="utf-8"))

    def list_campaigns(self) -> list[dict]:
        """Lightweight summaries (newest first) for a campaign-history view."""
        if not self.dir.is_dir():
            return []
        out: list[dict] = []
        for path in sorted(self.dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            out.append(
                {
                    "id": data.get("id", path.stem),
                    "domain": data.get("config", {}).get("domain", ""),
                    "status": data.get("status", ""),
                    "phases": len(data.get("phases", [])),
                    "created_at": data.get("created_at", ""),
                }
            )
        return out
