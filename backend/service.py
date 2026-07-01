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
from uuid import uuid4

from ai_framework.agent.contracts import Budget, Run, RunConfig

if TYPE_CHECKING:
    from backend.pillars import PlatformServices
from ai_framework.agent.loop import run_loop
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import Backend
from ai_framework.router.accounts import AccountStore
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool


def default_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(HttpGetTool())
    reg.register(NoteFindingTool())
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
    ) -> None:
        self._registry = registry or default_registry()
        self._memory_path = memory_path
        self._budget = budget
        self.accounts = accounts or AccountStore()
        self._runs: dict[str, Run] = {}
        self._lock = threading.Lock()
        self._pillars: PlatformServices | None = None

    @property
    def pillars(self) -> PlatformServices:
        """Knowledge base, vuln search, defense, labs, and i18n — built once on first use."""
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
        try:
            backend = self._backend_for(config)
            run_loop(config, backend, self._registry, memory, self._budget, run=run)
        except Exception as exc:  # noqa: BLE001 - surface to the console, don't lose the run
            run.outcome = "error"
            run.error = f"{type(exc).__name__}: {exc}"

    def start_run(self, config: RunConfig) -> str:
        run = Run(config=config)
        run_id = uuid4().hex
        with self._lock:
            self._runs[run_id] = run
        thread = threading.Thread(target=self._execute, args=(config, run), daemon=True)
        thread.start()
        return run_id

    def get_run(self, run_id: str) -> Run | None:
        with self._lock:
            return self._runs.get(run_id)

    def memory_summary(self, target: str = "") -> dict:
        """What Hermes remembers (optionally for one target) — backs the memory view."""
        if not self._memory_path:
            return {"total": 0, "by_kind": {}, "targets": [], "recent": []}
        return JsonlMemoryStore(self._memory_path).summary(target)
