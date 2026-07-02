"""RunService — the orchestration layer the HTTP API sits on.

Holds the tool registry, the AI account store, and a model-backend factory; starts runs and
keeps their results addressable by id. Runs execute on a background thread so the HTTP call
returns an id immediately and the console can poll the transcript as it grows (Run.outcome
flips from "incomplete" to done/step_budget_reached/error). Socket-free, so it stays unit
testable. ``defense/`` can reuse this unchanged — only the goal/objective differs.
"""

from __future__ import annotations

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
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import Backend
from ai_framework.notes.remediation import Remediator
from ai_framework.notes.report import render_json, render_markdown
from ai_framework.notes.store import JsonlFindingStore
from ai_framework.router.accounts import AccountStore
from ai_framework.router.usage import UsageStore
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
        # Stop-button plumbing: one cancel event per in-flight run/campaign, set()-able from a
        # request handler and polled by run_loop between turns. In-memory only — a run started
        # before a process restart can no longer be cancelled, same as it can no longer be polled.
        self._cancel_events: dict[str, threading.Event] = {}
        self._campaign_cancel: dict[str, threading.Event] = {}

    def _findings(self) -> JsonlFindingStore | None:
        return JsonlFindingStore(self._findings_path) if self._findings_path else None

    def _assets(self) -> JsonlAssetStore | None:
        return JsonlAssetStore(self._assets_path) if self._assets_path else None

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
        # consecutive phases ⇒ the target looks well-defended (hardened).
        made_progress = bool(new_techs - prev_techs) or new_confirmed > prev_confirmed
        campaign.hardened_streak = 0 if made_progress else campaign.hardened_streak + 1
        campaign.status = (
            CampaignStatus.hardened if is_hardened(campaign) else CampaignStatus.awaiting_user
        )
        self._save_campaign(campaign)

    def _run_phases(self, campaign: Campaign, cancel: threading.Event) -> None:
        """Autopilot: chain phases with no operator pause until a stop condition.

        Runs one phase after another on this worker thread, stopping when the target looks
        ``hardened``, the operator ``stopped`` it, a phase ``error``ed, or the ``max_phases``
        budget is spent (→ ``completed``). This is what makes a single request drive the whole
        engagement end to end.
        """
        while True:
            self._run_phase(campaign, cancel)
            if campaign.status in (
                CampaignStatus.stopped,
                CampaignStatus.error,
                CampaignStatus.hardened,
            ):
                return
            if campaign.phase_count >= campaign.config.max_phases:
                campaign.status = CampaignStatus.completed
                self._save_campaign(campaign)
                return

    def start_campaign(self, config: CampaignConfig) -> str:
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
        automatically, and the run drives itself to ``hardened``/``completed`` with no more input.
        """
        auto = config.model_copy(update={"autopilot": True})
        return self.start_campaign(auto)

    def continue_campaign(self, campaign_id: str) -> bool:
        campaign = self._get_campaign_obj(campaign_id)
        if campaign is None or campaign.status not in (
            CampaignStatus.awaiting_user,
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
        ctx = ToolContext(authorized_targets=campaign.config.all_authorized())
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
