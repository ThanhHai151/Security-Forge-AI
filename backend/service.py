"""RunService — the orchestration layer the HTTP API sits on.

Holds the tool registry, the AI account store, and a model-backend factory; starts runs and
keeps their results addressable by id. Runs execute on a background thread so the HTTP call
returns an id immediately and the console can poll the transcript as it grows (Run.outcome
flips from "incomplete" to done/step_budget_reached/error). Socket-free, so it stays unit
testable. ``defense/`` can reuse this unchanged — only the goal/objective differs.
"""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING

from ai_framework.agent.assets import JsonlAssetStore
from ai_framework.agent.campaign import (
    ApprovalStatus,
    Campaign,
    CampaignConfig,
    CampaignStatus,
    CampaignStore,
    CoverageItem,
    CoverageStatus,
    PendingApproval,
    coverage_signature,
    derive_coverage,
    is_hardened,
    record_manual_action,
)
from ai_framework.agent.contracts import Budget, Run, RunConfig, ToolCall
from ai_framework.agent.guardrails import GuardrailController
from ai_framework.agent.loop import run_loop
from ai_framework.agent.opsec import Pacer
from ai_framework.agent.run_store import JsonRunStore
from ai_framework.agent.system import campaign_context_block
from ai_framework.agent.verify import FindingVerifier
from ai_framework.evidence import EvidenceLedger
from ai_framework.harness.limits import EngagementLimiter
from ai_framework.harness.policy import evaluate_action, preflight_blockers
from ai_framework.harness.runtime import action_request_for_tool, approval_token_for_call
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import Backend
from ai_framework.notebook.contracts import NodeStatus
from ai_framework.notebook.raw_log import RawLogStore
from ai_framework.notebook.store import NotebookStore
from ai_framework.notes.contracts import Finding, Severity
from ai_framework.notes.remediation import Remediator
from ai_framework.notes.report import render_json, render_markdown
from ai_framework.notes.store import JsonlFindingStore
from ai_framework.report.sarif import notebook_to_sarif
from ai_framework.research.archetype import ArchetypeStore
from ai_framework.router.accounts import AccountStore
from ai_framework.router.usage import UsageStore
from ai_framework.supervisor.contracts import SessionContext
from ai_framework.supervisor.service import SupervisorService
from ai_framework.taxonomy.tree import Taxonomy
from ai_framework.tools.base import ToolContext, ToolRegistry

if TYPE_CHECKING:
    from backend.pillars import PlatformServices
from ai_framework.tools.auth import LoginTool, SetAuthTool
from ai_framework.tools.browser import BrowserRenderTool
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool, RecordAssetTool
from ai_framework.tools.external import ExternalReconTool
from ai_framework.tools.jwt import JwtAttackTool
from ai_framework.tools.security import (
    DecodeEncodeTool,
    HttpRequestTool,
    InspectHeadersTool,
    RobotsSitemapTool,
)
from ai_framework.tools.skills_tool import LoadSkillTool

_AUTONOMOUS_ENV = "SECFORGE_ENABLE_AUTONOMOUS"
_REQUIRE_ROE_ENV = "SECFORGE_REQUIRE_ROE"


class AutonomousDisabledError(RuntimeError):
    """Raised when a caller hits the legacy autonomous engine without opting in.

    SecForge no longer executes pentest actions itself by default — that job moved to an
    external coding agent (e.g. Claude Code) guided by the Expert Supervisor
    (``ai_framework.supervisor``). The old engine (``ai_framework.agent``/this class's
    run/campaign methods) is kept for a future "Continuous" redesign, not deleted, but it
    is gated off so a stale frontend build can't silently fall back to autonomous execution.
    """


def _autonomous_enabled() -> bool:
    return os.getenv(_AUTONOMOUS_ENV, "").strip().lower() in {"1", "true", "yes"}


def _roe_required() -> bool:
    return os.getenv(_REQUIRE_ROE_ENV, "1").strip().lower() not in {"0", "false", "no"}


def _require_ready_roe(config: RunConfig) -> None:
    if not _roe_required():
        return
    if config.rules_of_engagement is None:
        raise PermissionError(
            "autonomous execution requires a validated rules_of_engagement object"
        )
    blockers = preflight_blockers(config.rules_of_engagement, primary_target=config.target)
    if blockers:
        raise PermissionError("RoE preflight failed: " + "; ".join(blockers))


def default_registry() -> ToolRegistry:
    reg = ToolRegistry()
    for tool in (
        HttpGetTool(),
        NoteFindingTool(),
        RecordAssetTool(),
        HttpRequestTool(),
        InspectHeadersTool(),
        RobotsSitemapTool(),
        DecodeEncodeTool(),
        JwtAttackTool(),
        LoginTool(),
        SetAuthTool(),
        ExternalReconTool(),
        BrowserRenderTool(),
        LoadSkillTool(),
    ):
        reg.register(tool)
    return reg


def make_backend(name: str) -> Backend:
    """Factory for the simple, no-config backends (used directly by tests)."""
    if name == "offline":
        from ai_framework.models.offline import OfflineBackend

        return OfflineBackend()
    if name == "anthropic":
        from ai_framework.models.anthropic_backend import AnthropicBackend

        return AnthropicBackend()
    if name == "openrouter":
        from ai_framework.models.openrouter_backend import OpenRouterBackend

        return OpenRouterBackend()
    raise ValueError(f"unknown backend: {name}")


class RunService:
    def __init__(
        self,
        registry: ToolRegistry | None = None,
        memory_path: str | None = "memory_store.jsonl",
        budget: Budget | None = None,
        accounts: AccountStore | None = None,
        usage: UsageStore | None = None,
        findings_path: str | None = "findings_store.jsonl",
        runs_dir: str | None = "runs_store",
        campaigns_dir: str | None = "campaigns_store",
        assets_path: str | None = "assets_store.jsonl",
        notebook_dir: str | None = "notebook_store",
        archetype_path: str | None = "archetype_store.json",
        raw_log_path: str | None = "raw_output_store.jsonl",
        evidence_path: str | None = None,
    ) -> None:
        self._registry = registry or default_registry()
        self._memory_path = memory_path
        self._findings_path = findings_path
        self._assets_path = assets_path
        self._budget = budget
        self.accounts = accounts or AccountStore()
        self.usage = usage or UsageStore()
        self._runs: dict[str, Run] = {}
        self._run_store = JsonRunStore(runs_dir) if runs_dir else None
        self._campaigns: dict[str, Campaign] = {}
        self._campaign_store = CampaignStore(campaigns_dir) if campaigns_dir else None
        self._lock = threading.Lock()
        self._pillars: PlatformServices | None = None
        self._notebook_dir = notebook_dir or "notebook_store"
        self._archetype_path = archetype_path or "archetype_store.json"
        self._raw_log_path = raw_log_path or "raw_output_store.jsonl"
        self._evidence_path = evidence_path or os.getenv(
            "SECFORGE_EVIDENCE", "evidence_ledger.jsonl"
        )
        self._raw_log_store: RawLogStore | None = None
        self._taxonomy = Taxonomy()
        self._supervisor: SupervisorService | None = None
        # Stop-button plumbing: one cancel event per in-flight run/campaign, set()-able from a
        # request handler and polled by run_loop between turns. In-memory only — a run started
        # before a process restart can no longer be cancelled, same as it can no longer be polled.
        self._cancel_events: dict[str, threading.Event] = {}
        self._campaign_cancel: dict[str, threading.Event] = {}
        self._campaign_limiters: dict[str, EngagementLimiter] = {}

    def _findings(self) -> JsonlFindingStore | None:
        return JsonlFindingStore(self._findings_path) if self._findings_path else None

    def _assets(self) -> JsonlAssetStore | None:
        return JsonlAssetStore(self._assets_path) if self._assets_path else None

    def _evidence(self) -> EvidenceLedger | None:
        return EvidenceLedger(self._evidence_path) if self._evidence_path else None

    def evidence_status(self) -> dict:
        ledger = self._evidence()
        if ledger is None:
            return {"enabled": False, "valid": False, "detail": "evidence ledger disabled"}
        valid, detail = ledger.verify()
        return {"enabled": True, "valid": valid, "detail": detail}

    def assets_summary(self, target: str = "") -> dict:
        """Discovered attack surface (optionally for one target) — backs the recon view."""
        store = self._assets()
        if store is None:
            return {"total": 0, "by_kind": {}, "values": {}, "targets": [], "recent": []}
        return store.summary(target)

    @property
    def pillars(self) -> PlatformServices:
        """Knowledge base, vuln search, defense, and i18n — built once on first use."""
        if self._pillars is None:
            from backend.pillars import PlatformServices

            self._pillars = PlatformServices()
        return self._pillars

    @property
    def supervisor(self) -> SupervisorService:
        """The Expert Supervisor — built once on first use. Never touches ``ToolRegistry``,
        ``Backend``, or ``accounts``; see ``ai_framework.supervisor`` for why."""
        if self._supervisor is None:
            self._supervisor = SupervisorService(
                taxonomy=self._taxonomy,
                notebooks=NotebookStore(self._notebook_dir, taxonomy=self._taxonomy),
                archetypes=ArchetypeStore(self._archetype_path),
            )
        return self._supervisor

    # ── Expert Supervisor + Hermes notebook (the new advisory flow) ──────────────────

    def advise(
        self,
        domain: str,
        question: str,
        mode: str = "blackbox",
        project_path: str | None = None,
        scan_mode: str = "standard",
        vendor: str = "generic",
        rules_of_engagement: dict | None = None,
    ) -> dict:
        # Validate at the service boundary so JSON-shaped vendor/RoE values become the typed
        # control-plane objects before the Supervisor ever renders them into model context.
        ctx = SessionContext.model_validate(
            {
                "domain": domain,
                "question": question,
                "mode": mode,
                "project_path": project_path,
                "scan_mode": scan_mode,
                "vendor": vendor,
                "rules_of_engagement": rules_of_engagement,
            }
        )
        return self.supervisor.advise(ctx).model_dump(mode="json")

    def get_taxonomy_tree(self) -> list[dict]:
        return self.supervisor.taxonomy.tree()

    def list_archetypes(self) -> list[dict]:
        return [h.model_dump() for h in self.supervisor.archetypes.list_all()]

    def list_notebook_domains(self) -> list[dict]:
        return self.supervisor.notebooks.list_domains()

    def get_notebook(self, domain: str) -> dict:
        return self.supervisor.notebooks.get_or_create(domain).model_dump(mode="json")

    def get_notebook_tree(self, domain: str) -> dict:
        return {"domain": domain, "tree": self.supervisor.notebooks.tree_view(domain)}

    def notebook_sarif(self, domain: str) -> dict:
        """Export a domain's confirmed/unconfirmed findings as a SARIF 2.1.0 document for CI
        upload (GitHub code scanning, etc.). Deterministic — no AI call, no target access."""
        notebook = self.supervisor.notebooks.get_or_create(domain)
        return notebook_to_sarif(notebook, taxonomy=self._taxonomy)

    def update_notebook_node(
        self,
        domain: str,
        node_id: str,
        status: str,
        note: str = "",
        finding: dict | None = None,
        severity: str = "",
    ) -> dict:
        """Set one node's status. A human-set ``confirmed`` also writes a linked ``Finding``
        (auto-ingest never reaches this path with ``confirmed`` — see
        ``NotebookStore.ingest_promote``). This always clears ``in_progress`` on the node —
        see ``NotebookStore.set_status``. ``severity`` (critical|high|medium|low|info) scores
        the finding by real impact in the exported report/SARIF."""
        node_status = NodeStatus(status)
        notebook = self.supervisor.notebooks.set_status(
            domain, node_id, node_status, note=note, updated_by="user", severity=severity,
        )
        store = self._findings()
        if node_status == NodeStatus.confirmed and finding and store is not None:
            record = Finding(
                target=domain,
                title=str(finding.get("title") or node_id),
                detail=str(finding.get("detail", "")),
                severity=Severity.parse(finding.get("severity", "medium")),
                evidence=str(finding.get("evidence", "")),
                tags=[node_id],
            )
            store.write(record)
            notebook = self.supervisor.notebooks.link_finding(domain, node_id, record.id)
        return notebook.model_dump(mode="json")

    def set_notebook_archetype(self, domain: str, archetype: str) -> dict:
        return self.supervisor.notebooks.set_archetype(domain, archetype).model_dump(mode="json")

    def mark_notebook_in_progress(self, domain: str, node_id: str) -> dict:
        """Manually flag ``node_id`` as the one thing currently being tested on this target
        (normally set automatically by ``advise()`` — see ``NotebookStore.set_in_progress``)."""
        return self.supervisor.notebooks.set_in_progress(domain, node_id).model_dump(mode="json")

    def list_notebook_tree_roots(self) -> list[dict]:
        """Root domains with their nested subdomains, for the sidebar."""
        return self.supervisor.notebooks.roots_and_children()

    def add_notebook_child(self, parent_domain: str, child: str) -> dict:
        """Attach a discovered subdomain under its parent."""
        notebook = self.supervisor.notebooks.add_child(parent_domain, child)
        return notebook.model_dump(mode="json")

    def delete_notebook_domain(self, domain: str) -> bool:
        """Permanently remove a domain's notebook. Returns False if it wasn't tracked."""
        return self.supervisor.notebooks.delete(domain)

    def add_notebook_chain(self, domain: str, from_node: str, to_node: str, note: str = "") -> dict:
        return self.supervisor.notebooks.add_chain(domain, from_node, to_node, note).model_dump(
            mode="json"
        )

    def ingest_notebook_output(self, domain: str, text: str) -> dict:
        """Fold an external coding agent's pasted raw output into the notebook.

        Persists ``text`` verbatim (``RawLogStore``) before any parsing, and only ever
        promotes to ``unconfirmed`` or files a marker-justified custom node — see
        ``ai_framework.supervisor.ingest`` for the full contract.
        """
        from ai_framework.supervisor.ingest import ingest_output

        result = ingest_output(
            domain, text, self.supervisor.notebooks, self.supervisor.taxonomy, self._raw_log()
        )
        notebook = self.supervisor.notebooks.get_or_create(domain)
        return {
            "notebook": notebook.model_dump(mode="json"),
            "promoted": result.promoted,
            "custom_added": result.custom_added,
        }

    def _raw_log(self) -> RawLogStore:
        if self._raw_log_store is None:
            self._raw_log_store = RawLogStore(self._raw_log_path)
        return self._raw_log_store

    def _backend_for(self, config: RunConfig) -> Backend:
        """Resolve the backend: the native rotating router, or a simple named backend."""
        if config.backend == "router":
            from ai_framework.router.router import RouterBackend

            return RouterBackend(self.accounts, usage=self.usage)
        return make_backend(config.backend)

    def _execute(self, config: RunConfig, run: Run, cancel: threading.Event) -> None:
        """Run the loop on a worker thread, recording errors onto the Run for polling."""
        memory = JsonlMemoryStore(self._memory_path) if self._memory_path else None
        guardrail = GuardrailController()
        pacer = Pacer(config.opsec_min_interval, config.opsec_jitter)
        checkpoint = self._run_store.save if self._run_store else None
        try:
            backend = self._backend_for(config)
            run_loop(
                config,
                backend,
                self._registry,
                memory,
                self._budget,
                run=run,
                guardrail=guardrail,
                pacer=pacer,
                findings=self._findings(),
                on_turn=checkpoint,
                verifier=FindingVerifier(),
                assets=self._assets(),
                cancel=cancel,
                evidence=self._evidence(),
            )
        except Exception as exc:  # noqa: BLE001 - surface to the console, don't lose the run
            run.outcome = "error"
            run.error = f"{type(exc).__name__}: {exc}"
        finally:
            if self._run_store is not None:
                self._run_store.save(run)  # persist final state (incl. errors)
            with self._lock:
                self._cancel_events.pop(run.id, None)

    def start_run(self, config: RunConfig) -> str:
        if not _autonomous_enabled():
            raise AutonomousDisabledError(
                "Autonomous execution is disabled by default — SecForge no longer runs "
                f"pentest actions itself. Set {_AUTONOMOUS_ENV}=1 to re-enable the legacy "
                "engine, or use POST /supervisor/advise instead."
            )
        _require_ready_roe(config)
        run = Run(config=config)
        cancel = threading.Event()
        with self._lock:
            self._runs[run.id] = run
            self._cancel_events[run.id] = cancel
        thread = threading.Thread(target=self._execute, args=(config, run, cancel), daemon=True)
        thread.start()
        return run.id

    def stop_run(self, run_id: str) -> bool:
        """Signal a running Hermes loop to stop before its next turn (Stop button)."""
        with self._lock:
            cancel = self._cancel_events.get(run_id)
        if cancel is None:
            return False
        cancel.set()
        return True

    def get_run(self, run_id: str) -> Run | None:
        with self._lock:
            run = self._runs.get(run_id)
        if run is not None:
            return run
        # Fall back to disk: a run from a previous process is still reloadable/replayable.
        return self._run_store.load(run_id) if self._run_store else None

    def list_runs(self) -> list[dict]:
        """Summaries of persisted runs (newest first) — backs a run-history view."""
        return self._run_store.list_runs() if self._run_store else []

    def memory_summary(self, target: str = "") -> dict:
        """What Hermes remembers (optionally for one target) — backs the memory view."""
        if not self._memory_path:
            return {"total": 0, "by_kind": {}, "targets": [], "recent": []}
        return JsonlMemoryStore(self._memory_path).summary(target)

    def findings_summary(self, target: str = "") -> dict:
        """Findings captured so far (optionally for one target) — backs the findings view."""
        store = self._findings()
        if store is None:
            return {"total": 0, "by_severity": {}, "targets": [], "recent": []}
        return store.summary(target)

    def run_report(self, run_id: str, fmt: str = "md") -> str | dict | None:
        """Render one run's findings as a Markdown or JSON pentest report.

        Each finding is matched to its knowledge-base class so the report carries concrete fix
        guidance inline (weakness → remediation), the same curated text the defensive reviewer uses.
        """
        store = self._findings()
        run = self.get_run(run_id)
        if store is None or run is None:
            return None
        findings = store.for_run(run_id)
        remediator = Remediator(self.pillars.kb)
        if fmt == "json":
            return render_json(findings, target=run.config.target, remediator=remediator)
        return render_markdown(
            findings, target=run.config.target, goal=run.config.goal, remediator=remediator
        )

    # ── Campaigns: the continuous ("infinite") engagement layer ──────────────────────

    def _get_campaign_obj(self, campaign_id: str) -> Campaign | None:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
        if campaign is not None:
            return campaign
        return self._campaign_store.load(campaign_id) if self._campaign_store else None

    def _save_campaign(self, campaign: Campaign) -> None:
        with self._lock:
            self._campaigns[campaign.id] = campaign
        if self._campaign_store is not None:
            self._campaign_store.save(campaign)

    def _campaign_limiter(self, campaign: Campaign) -> EngagementLimiter | None:
        if campaign.config.rules_of_engagement is None:
            return None
        with self._lock:
            limiter = self._campaign_limiters.get(campaign.id)
            if limiter is None:
                limiter = EngagementLimiter(campaign.config.rules_of_engagement)
                self._campaign_limiters[campaign.id] = limiter
            return limiter

    def _phase_goal(self, campaign: Campaign, phase_index: int) -> str:
        """Compose the objective for one phase — recon-first, then progressively deeper."""
        domain = campaign.config.domain
        if phase_index == 0:
            return (
                f"Recon and map the attack surface of {domain}; identify the technology stack "
                "and likely vulnerability classes, and probe read-only. Do not modify data — "
                "propose any state-changing test for manual approval instead."
            )
        return (
            f"Continue the authorized engagement against {domain}. Go deeper on confirmed leads "
            "and wider into untried techniques; do not repeat what earlier phases already tried. "
            "Keep every action read-only unless the operator approves a state-changing test."
        )

    def _run_phase(self, campaign: Campaign, cancel: threading.Event | None = None) -> None:
        """Execute one phase (a bounded run) on a worker thread and fold in its results."""
        cfg = campaign.config
        phase_index = campaign.phase_count  # 0-based index of the phase we are about to run
        untried = [c.technique for c in campaign.coverage if c.status == CoverageStatus.untried]
        addon = campaign_context_block(phase_index + 1, untried, campaign.carry_over_plan)
        run_config = RunConfig(
            goal=self._phase_goal(campaign, phase_index),
            target=cfg.target_url(),
            step_budget=cfg.phase_step_budget,
            backend=cfg.backend,
            model=cfg.model,
            base_url=cfg.base_url,
            authorized_targets=cfg.all_authorized(),
            rules_of_engagement=cfg.rules_of_engagement,
            opsec_min_interval=cfg.opsec_min_interval,
            opsec_jitter=cfg.opsec_jitter,
        )
        run = Run(config=run_config)
        with self._lock:
            self._runs[run.id] = run
        campaign.phases.append(run.id)
        campaign.status = CampaignStatus.running
        self._save_campaign(campaign)

        def on_hold(call: ToolCall, reasoning: str) -> None:
            campaign.pending_approvals.append(
                PendingApproval(phase=phase_index + 1, tool_call=call, rationale=reasoning)
            )

        memory = JsonlMemoryStore(self._memory_path) if self._memory_path else None
        checkpoint = self._run_store.save if self._run_store else None
        prior = list(campaign.coverage)
        # Autopilot may opt into running state-changing actions without a manual approval hold —
        # the authorized-scope gate still bounds every call. Default stays safe (hold for approval).
        hold_mutating = not cfg.auto_approve_mutating
        try:
            backend = self._backend_for(run_config)
            run_loop(
                run_config,
                backend,
                self._registry,
                memory,
                self._budget,
                run=run,
                guardrail=GuardrailController(),
                pacer=Pacer(cfg.opsec_min_interval, cfg.opsec_jitter),
                findings=self._findings(),
                on_turn=checkpoint,
                hold_mutating=hold_mutating,
                on_hold=on_hold,
                system_addon=addon,
                verifier=FindingVerifier(),
                assets=self._assets(),
                cancel=cancel,
                evidence=self._evidence(),
                limiter=self._campaign_limiter(campaign),
            )
        except Exception as exc:  # noqa: BLE001 - surface to the console, don't lose state
            run.outcome = "error"
            run.error = f"{type(exc).__name__}: {exc}"
            campaign.status = CampaignStatus.error
            campaign.error = run.error
            if self._run_store is not None:
                self._run_store.save(run)
            self._save_campaign(campaign)
            return
        if self._run_store is not None:
            self._run_store.save(run)

        if run.outcome == "stopped":
            # The operator hit Stop mid-phase — stop_campaign() already set the campaign status;
            # don't let the coverage/hardened-streak logic below recompute it back to "running".
            campaign.status = CampaignStatus.stopped
            self._save_campaign(campaign)
            return

        # Fold this phase's transcript into the tried/untried map and decide what's next.
        prev_confirmed, _ = coverage_signature(prior)
        prev_techs = {c.technique for c in prior}
        campaign.coverage = derive_coverage(run, prior, phase_index + 1)
        new_confirmed, _ = coverage_signature(campaign.coverage)
        new_techs = {c.technique for c in campaign.coverage}
        if run.transcript and run.transcript[-1].next_plan:
            campaign.carry_over_plan = run.transcript[-1].next_plan
        # Progress = a new confirmed finding OR a newly surfaced technique. No progress across
        # Consecutive phases without new evidence mean only that this budget found nothing new.
        made_progress = bool(new_techs - prev_techs) or new_confirmed > prev_confirmed
        campaign.hardened_streak = 0 if made_progress else campaign.hardened_streak + 1
        campaign.status = (
            CampaignStatus.no_new_findings
            if is_hardened(campaign)
            else CampaignStatus.awaiting_user
        )
        self._save_campaign(campaign)

    def _run_phases(self, campaign: Campaign, cancel: threading.Event) -> None:
        """Autopilot: chain phases with no operator pause until a stop condition.

        Runs one phase after another on this worker thread, stopping when the target looks
        no-new-findings, the operator ``stopped`` it, a phase ``error``ed, or the ``max_phases``
        budget is spent (→ ``completed``). This is what makes a single request drive the whole
        engagement end to end.
        """
        while True:
            self._run_phase(campaign, cancel)
            if campaign.status in (
                CampaignStatus.stopped,
                CampaignStatus.error,
                CampaignStatus.no_new_findings,
                CampaignStatus.hardened,
            ):
                return
            if campaign.phase_count >= campaign.config.max_phases:
                campaign.status = CampaignStatus.completed
                self._save_campaign(campaign)
                return

    def start_campaign(self, config: CampaignConfig) -> str:
        if not _autonomous_enabled():
            raise AutonomousDisabledError(
                "Autonomous execution is disabled by default — Continuous campaigns are "
                f"locked pending a redesign. Set {_AUTONOMOUS_ENV}=1 to re-enable the legacy "
                "engine, or use POST /supervisor/advise instead."
            )
        _require_ready_roe(
            RunConfig(
                goal="authorized campaign preflight",
                target=config.target_url(),
                authorized_targets=config.all_authorized(),
                rules_of_engagement=config.rules_of_engagement,
            )
        )
        campaign = Campaign(config=config)
        # Seed the map with the one lead we always start from: reconnaissance.
        campaign.coverage = [
            CoverageItem(technique="recon", description="initial reconnaissance", phase=1)
        ]
        self._save_campaign(campaign)
        cancel = threading.Event()
        with self._lock:
            self._campaign_cancel[campaign.id] = cancel
        # Autopilot chains phases automatically; otherwise one phase runs and pauses for review.
        if config.autopilot:
            threading.Thread(
                target=self._run_phases, args=(campaign, cancel), daemon=True
            ).start()
        else:
            threading.Thread(
                target=self._run_phase, args=(campaign, cancel), daemon=True
            ).start()
        return campaign.id

    def start_pentest(self, config: CampaignConfig) -> str:
        """One-shot autonomous pentest: force autopilot on and run to a stop condition.

        This backs ``POST /pentest`` — the "just give it an address" surface. The caller supplies
        only the target (domain/URL); recon-first phase goals and the coverage map are generated
        automatically, and the run drives itself to no-new-findings/``completed``.
        """
        auto = config.model_copy(update={"autopilot": True})
        return self.start_campaign(auto)

    def continue_campaign(self, campaign_id: str) -> bool:
        campaign = self._get_campaign_obj(campaign_id)
        if campaign is None or campaign.status not in (
            CampaignStatus.awaiting_user,
            CampaignStatus.no_new_findings,
            CampaignStatus.hardened,
        ):
            return False
        # Fresh cancel event per resumed phase, so Stop always targets the phase actually running.
        cancel = threading.Event()
        with self._lock:
            self._campaign_cancel[campaign_id] = cancel
        threading.Thread(target=self._run_phase, args=(campaign, cancel), daemon=True).start()
        return True

    def stop_campaign(self, campaign_id: str) -> bool:
        campaign = self._get_campaign_obj(campaign_id)
        if campaign is None:
            return False
        campaign.status = CampaignStatus.stopped
        self._save_campaign(campaign)
        with self._lock:
            cancel = self._campaign_cancel.get(campaign_id)
        if cancel is not None:
            cancel.set()  # interrupt the in-flight phase's run_loop before its next turn
        return True

    def approve_action(self, campaign_id: str, approval_id: str) -> bool:
        """Execute one operator-approved held action — the only way a mutating call ever runs."""
        campaign = self._get_campaign_obj(campaign_id)
        if campaign is None:
            return False
        approval = next(
            (p for p in campaign.pending_approvals if p.id == approval_id), None
        )
        if approval is None or approval.status != ApprovalStatus.pending:
            return False
        roe = campaign.config.rules_of_engagement
        ctx = ToolContext(
            authorized_targets=campaign.config.all_authorized(),
            rules_of_engagement=roe,
            primary_target=campaign.config.target_url(),
            limiter=self._campaign_limiter(campaign),
            audit=self._evidence(),
            run_id=campaign.id,
        )
        if roe is not None:
            tool = self._registry.get(approval.tool_call.name)
            request = action_request_for_tool(approval.tool_call, tool, ctx.primary_target)
            decision = evaluate_action(roe, request, primary_target=ctx.primary_target)
            token = approval_token_for_call(approval.tool_call, decision)
            ctx.approved_action_tokens.add(token)
        Pacer(campaign.config.opsec_min_interval, campaign.config.opsec_jitter).wait(
            campaign.config.domain
        )
        result = self._registry.execute(approval.tool_call, ctx)
        approval.status = ApprovalStatus.approved
        approval.result_log = result.log
        campaign.coverage = record_manual_action(
            campaign.coverage, approval.tool_call, result.ok, approval.phase
        )
        self._save_campaign(campaign)
        return True

    def reject_action(self, campaign_id: str, approval_id: str) -> bool:
        campaign = self._get_campaign_obj(campaign_id)
        if campaign is None:
            return False
        approval = next(
            (p for p in campaign.pending_approvals if p.id == approval_id), None
        )
        if approval is None:
            return False
        approval.status = ApprovalStatus.rejected
        self._save_campaign(campaign)
        return True

    def get_campaign(self, campaign_id: str) -> dict | None:
        """Full campaign state with each phase's run transcript inlined (for the terminal UI)."""
        campaign = self._get_campaign_obj(campaign_id)
        if campaign is None:
            return None
        data = campaign.model_dump(mode="json")
        phase_runs = []
        for run_id in campaign.phases:
            run = self.get_run(run_id)
            if run is not None:
                phase_runs.append(run.model_dump(mode="json"))
        data["phase_runs"] = phase_runs
        return data

    def list_campaigns(self) -> list[dict]:
        return self._campaign_store.list_campaigns() if self._campaign_store else []

    # ── Defense: static assessment, with an optional live attack of the running app ──────
    # Standalone — deliberately does not feed the Hermes notebook (see ai_framework.notebook);
    # that notebook is red-team-only, scoped to live URL targets.

    def defense_autopilot(
        self,
        path: str,
        serve_url: str | None = None,
        deps_online: bool = False,
        backend: str = "offline",
        model: str | None = None,
        base_url: str | None = None,
        authorized_targets: set[str] | None = None,
    ) -> dict:
        """Assess a local project and, when it is running, attack it — then guide the fix.

        Always returns the static code review + dependency (SCA) report (fix guidance is attached
        to each code finding via the catalog "Defenses" section). When ``serve_url`` points at the
        project's running instance (localhost or an authorized host), it also launches an autopilot
        pentest against it and returns ``campaign_id`` so the caller can poll the live findings.
        This is the "review the code *and* attack the running app" flow the defense brief asks for.
        """
        result = self.pillars.defense_scan(path, deps_online=deps_online)
        if "error" in result:
            return result
        campaign_id: str | None = None
        if serve_url:
            cfg = CampaignConfig(
                domain=serve_url,
                backend=backend,
                model=model,
                base_url=base_url,
                authorized_targets=set(authorized_targets or []),
            )
            campaign_id = self.start_pentest(cfg)
        result["campaign_id"] = campaign_id
        return result
