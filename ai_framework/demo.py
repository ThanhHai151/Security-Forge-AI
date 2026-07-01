"""CLI demo: run the Hermes loop end to end and stream the transcript.

    python -m ai_framework.demo --goal "Recon the target" \\
        --target http://localhost:8000 --backend offline

Runs with no API key on the offline backend. Use ``--backend anthropic`` with
``ANTHROPIC_API_KEY`` set for the Claude backend.
"""

from __future__ import annotations

import argparse

from ai_framework.agent.contracts import Budget, RunConfig
from ai_framework.agent.loop import run_loop
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import Backend
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool


def _make_backend(name: str) -> Backend:
    if name == "offline":
        from ai_framework.models.offline import OfflineBackend

        return OfflineBackend()
    if name == "anthropic":
        from ai_framework.models.anthropic_backend import AnthropicBackend

        return AnthropicBackend()
    if name == "openrouter":
        from ai_framework.models.openrouter_backend import OpenRouterBackend

        return OpenRouterBackend()
    raise SystemExit(f"unknown backend: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SecForge Hermes loop demo")
    parser.add_argument("--goal", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--backend", default="offline", choices=["offline", "anthropic", "openrouter"]
    )
    parser.add_argument("--step-budget", type=int, default=10)
    parser.add_argument("--memory", default="memory_store.jsonl")
    parser.add_argument(
        "--headroom",
        type=int,
        default=0,
        metavar="WINDOW",
        help="enable Headroom with this context-window size (tokens); 0 = off",
    )
    args = parser.parse_args()

    registry = ToolRegistry()
    registry.register(HttpGetTool())
    registry.register(NoteFindingTool())

    config = RunConfig(
        goal=args.goal,
        target=args.target,
        step_budget=args.step_budget,
        backend=args.backend,
        authorized_targets={args.target},
    )
    memory = JsonlMemoryStore(args.memory)
    budget = Budget.from_window(args.headroom) if args.headroom else None
    if budget is not None:
        # Use a local exact tokenizer for accounting when available; else keep the
        # built-in heuristic. Ground-truth Claude counts need the Anthropic API.
        try:
            from ai_framework.headroom import set_token_counter, tiktoken_counter

            set_token_counter(tiktoken_counter())
            print("headroom  : using tiktoken for token accounting")
        except Exception:
            print("headroom  : tiktoken not installed; using char heuristic")
    run = run_loop(config, _make_backend(args.backend), registry, memory, budget)

    print(f"=== Run: {config.goal} -> {config.target} [{config.backend}] ===")
    for turn in run.transcript:
        print(f"\n--- Turn {turn.index} ---")
        print(f"reasoning : {turn.reasoning}")
        for tc in turn.tool_calls:
            print(f"action    : {tc.name} {tc.arguments}")
        for tr in turn.tool_results:
            head = tr.log.splitlines()[0] if tr.log else ""
            print(f"log       : [{'ok' if tr.ok else 'fail'}] {head}")
        print(f"next plan : {turn.next_plan}")
    print(f"\noutcome   : {run.outcome}")
    print(f"memory    : {len(memory.all())} records in {memory.path}")
    for i, report in enumerate(run.compaction_reports):
        acts = ", ".join(f"{a.kind}(-{a.tokens_saved}t)" for a in report.actions) or "none"
        fit_state = "ok" if report.within_budget else "OVER"
        print(
            f"headroom  : call {i} {report.tokens_before}->{report.tokens_after}t "
            f"(budget {report.input_budget}t, {fit_state}): {acts}"
        )


if __name__ == "__main__":
    main()
