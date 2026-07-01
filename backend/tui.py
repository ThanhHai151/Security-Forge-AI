"""Terminal UI — drive the Hermes agent loop interactively, in the terminal.

The dependency-free counterpart to the Web UI: prompt for a goal/target/backend, run the
loop, and stream the transcript turn by turn. Reuses the same contracts and ``run_loop`` as
``backend.service`` and ``ai_framework.demo`` — no HTTP, so it works fully offline.

Entered from the ``secforge`` launcher menu, or directly: ``python -m backend.tui``.
"""

from __future__ import annotations

from ai_framework.agent.contracts import Run, RunConfig
from ai_framework.agent.loop import run_loop
from ai_framework.memory.store import JsonlMemoryStore
from backend.service import default_registry, make_backend

BACKENDS = ("offline", "anthropic", "openrouter")


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return answer or default


def _choose_backend() -> str:
    print("\nBackends:")
    for i, name in enumerate(BACKENDS, 1):
        note = " (no API key needed)" if name == "offline" else ""
        print(f"  {i}) {name}{note}")
    raw = _ask("Choose backend", "1")
    if raw in BACKENDS:
        return raw
    if raw.isdigit() and 1 <= int(raw) <= len(BACKENDS):
        return BACKENDS[int(raw) - 1]
    return "offline"


def _stream_run(config: RunConfig) -> Run:
    """Run the loop and print each turn as it is recorded on the shared Run object."""
    registry = default_registry()
    memory = JsonlMemoryStore("memory_store.jsonl")
    run = Run(config=config)
    print(f"\n=== Run: {config.goal} -> {config.target} [{config.backend}] ===")
    try:
        run_loop(config, make_backend(config.backend), registry, memory, run=run)
    except Exception as exc:  # noqa: BLE001 - surface, don't crash the TUI
        run.outcome = "error"
        run.error = f"{type(exc).__name__}: {exc}"

    for turn in run.transcript:
        print(f"\n--- Turn {turn.index} ---")
        print(f"reasoning : {turn.reasoning}")
        for tc in turn.tool_calls:
            print(f"action    : {tc.name} {tc.arguments}")
        for tr in turn.tool_results:
            head = tr.log.splitlines()[0] if tr.log else ""
            print(f"log       : [{'ok' if tr.ok else 'fail'}] {head}")
        if turn.next_plan:
            print(f"next plan : {turn.next_plan}")
    print(f"\noutcome   : {run.outcome}")
    if run.error:
        print(f"error     : {run.error}")
    print(f"memory    : {len(memory.all())} records in {memory.path}")
    return run


def run_tui() -> None:
    print("SecForge - Terminal UI")
    print("Drive the agent loop from the terminal. Ctrl-C to quit.\n")
    while True:
        goal = _ask("Goal", "Recon the target")
        target = _ask("Target", "http://localhost:8000")
        backend = _choose_backend()
        budget = _ask("Step budget", "10")
        config = RunConfig(
            goal=goal,
            target=target,
            backend=backend,
            step_budget=int(budget) if budget.isdigit() else 10,
            authorized_targets={target},
        )
        _stream_run(config)
        if _ask("\nRun another? (y/N)", "n").lower() not in ("y", "yes"):
            print("Bye.")
            return


def main() -> None:
    try:
        run_tui()
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
