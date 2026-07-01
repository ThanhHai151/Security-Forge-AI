"""Step 5: memory persists across sessions, recalls top-K, and backs the anti-loop guard."""

from ai_framework.agent.contracts import MemoryKind, MemoryRecord, RunConfig, ToolCall
from ai_framework.agent.loop import run_loop
from ai_framework.memory.store import JsonlMemoryStore
from ai_framework.models.base import ActResponse
from ai_framework.models.offline import OfflineBackend
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.builtin import HttpGetTool, NoteFindingTool


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(HttpGetTool())
    reg.register(NoteFindingTool())
    return reg


def test_memory_persists_across_sessions(tmp_path, mock_server):
    path = tmp_path / "mem.jsonl"
    config = RunConfig(goal="recon", target=mock_server, authorized_targets={mock_server})

    run_loop(config, OfflineBackend(), _registry(), JsonlMemoryStore(path))
    # A fresh store reading the same file sees the first run's records.
    assert len(JsonlMemoryStore(path).all()) >= 1


def test_recall_ranks_by_relevance(tmp_path):
    store = JsonlMemoryStore(tmp_path / "mem.jsonl")
    store.write(MemoryRecord(id="1", kind=MemoryKind.lesson, target="other", body="a"))
    store.write(
        MemoryRecord(id="2", kind=MemoryKind.lesson, target="t", technique="sqli", body="b")
    )
    store.write(MemoryRecord(id="3", kind=MemoryKind.lesson, target="t", body="c"))

    top = store.recall(target="t", technique="sqli", k=2)
    assert top[0].id == "2"  # target + technique match ranks first
    assert {r.id for r in top} == {"2", "3"}  # both target matches beat the non-match


def test_recalled_memory_is_injected_into_system_prompt(tmp_path):
    path = tmp_path / "mem.jsonl"
    store = JsonlMemoryStore(path)
    target = "http://203.0.113.10"
    store.write(
        MemoryRecord(
            id="fact1",
            kind=MemoryKind.target_fact,
            target=target,
            technique="http_get",
            body="server header leaks nginx/1.18",
        )
    )

    seen_systems: list[str] = []

    class _Spy(OfflineBackend):
        def act(self, system, transcript, config, tools):
            seen_systems.append(system)
            return ActResponse(reasoning="stop", done=True)

    config = RunConfig(goal="x", target=target, authorized_targets={"203.0.113.10"})
    run_loop(config, _Spy(), _registry(), store)

    assert seen_systems  # the backend was called
    assert "Relevant memory recalled" in seen_systems[0]
    assert "nginx/1.18" in seen_systems[0]  # the recalled fact actually reached the model


def test_anti_loop_skips_known_dead_end(tmp_path):
    path = tmp_path / "mem.jsonl"
    store = JsonlMemoryStore(path)
    target = "http://203.0.113.9"
    # Pre-seed a failed attempt for the exact call the backend will emit.
    store.write(
        MemoryRecord(
            id="seed",
            kind=MemoryKind.attempt,
            target=target,
            technique="http_get",
            body='{"url": "http://203.0.113.9"}',
        )
    )

    class _AlwaysHttpGet(OfflineBackend):
        def act(self, system, transcript, config, tools):
            if len(transcript) >= 1:
                return ActResponse(reasoning="stop", done=True)
            return ActResponse(
                reasoning="retry",
                tool_calls=[ToolCall(id="t0-c0", name="http_get", arguments={"url": target})],
            )

    config = RunConfig(goal="x", target=target, authorized_targets={"203.0.113.9"})
    run = run_loop(config, _AlwaysHttpGet(), _registry(), store)

    result = run.transcript[0].tool_results[0]
    assert not result.ok
    assert "known dead end" in result.log  # never hit the network
