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

from ai_framework.agent.contracts import Budget, Run, RunConfig

if TYPE_CHECKING:
    from backend.pillars import PlatformServices
from ai_framework.agent.guardrails import GuardrailController
from ai_framework.agent.loop import run_loop
from ai_framework.agent.opsec import Pacer
from ai_framework.agent.run_store import JsonRunStore
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import Backend
from ai_framework.notes.report import render_json, render_markdown
from ai_framework.notes.store import JsonlFindingStore
from ai_framework.router.accounts import AccountStore
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool
from ai_framework.tools.security import (
    DecodeEncodeTool,
    HttpRequestTool,
    InspectHeadersTool,
    RobotsSitemapTool,
)


def default_registry() -> ToolRegistry:
    reg = ToolRegistry()
    for tool in (
        HttpGetTool(),
        NoteFindingTool(),
        HttpRequestTool(),
        InspectHeadersTool(),
        RobotsSitemapTool(),
        DecodeEncodeTool(),
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
        findings_path: str | None = "findings_store.jsonl",
        runs_dir: str | None = "runs_store",
    ) -> None:
        self._registry = registry or default_registry()
        self._memory_path = memory_path
        self._findings_path = findings_path
        self._budget = budget
        self.accounts = accounts or AccountStore()
        self._runs: dict[str, Run] = {}
        self._run_store = JsonRunStore(runs_dir) if runs_dir else None
        self._lock = threading.Lock()
        self._pillars: PlatformServices | None = None

    def _findings(self) -> JsonlFindingStore | None:
        return JsonlFindingStore(self._findings_path) if self._findings_path else None

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

            return RouterBackend(self.accounts)
        return make_backend(config.backend)

    def _execute(self, config: RunConfig, run: Run) -> None:
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
            )
        except Exception as exc:  # noqa: BLE001 - surface to the console, don't lose the run
            run.outcome = "error"
            run.error = f"{type(exc).__name__}: {exc}"
        finally:
            if self._run_store is not None:
                self._run_store.save(run)  # persist final state (incl. errors)

    def start_run(self, config: RunConfig) -> str:
        run = Run(config=config)
        with self._lock:
            self._runs[run.id] = run
        thread = threading.Thread(target=self._execute, args=(config, run), daemon=True)
        thread.start()
        return run.id

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
        """Render one run's findings as a Markdown or JSON pentest report."""
        store = self._findings()
        run = self.get_run(run_id)
        if store is None or run is None:
            return None
        findings = store.for_run(run_id)
        if fmt == "json":
            return render_json(findings, target=run.config.target)
        return render_markdown(findings, target=run.config.target, goal=run.config.goal)
