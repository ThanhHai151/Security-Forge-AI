"""The Stop button: RunService.stop_run / stop_campaign actually interrupt a live loop.

test_loop.py already proves run_loop() itself honors a cancel Event. These tests prove the
service wiring around it — that stop_run()/stop_campaign() reach the *right* event for the
run/campaign actually in flight, and that a campaign phase stopped mid-run doesn't have its
"stopped" status clobbered by the coverage/hardened bookkeeping that runs after run_loop returns.
"""

from __future__ import annotations

import threading
import time

from ai_framework.agent.campaign import CampaignConfig
from ai_framework.agent.contracts import RunConfig
from ai_framework.models.offline import OfflineBackend
from backend.service import RunService


def _service(tmp_path) -> RunService:
    return RunService(
        memory_path=str(tmp_path / "m.jsonl"),
        findings_path=str(tmp_path / "f.jsonl"),
        runs_dir=str(tmp_path / "runs"),
        campaigns_dir=str(tmp_path / "camp"),
    )


class _PausableBackend(OfflineBackend):
    """Blocks mid-turn until the test releases it — deterministic "caught it mid-run" timing,
    no sleep-and-hope race against how fast the offline backend can chew through turns."""

    def __init__(self) -> None:
        super().__init__()
        self.turn_started = threading.Event()
        self.may_proceed = threading.Event()

    def act(self, system, transcript, config, tools):
        self.turn_started.set()
        self.may_proceed.wait(timeout=5)
        self.may_proceed.clear()
        action = super().act(system, transcript, config, tools)
        action.done = False  # would otherwise finish on its own; force reliance on cancel
        return action


def _await(predicate, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition did not become true in time")


def test_stop_run_interrupts_a_live_single_run(tmp_path, mock_server):
    svc = _service(tmp_path)
    backend = _PausableBackend()
    svc._backend_for = lambda config: backend  # bypass the "offline" name lookup

    config = RunConfig(
        goal="x", target=mock_server, step_budget=1000, authorized_targets={mock_server}
    )
    run_id = svc.start_run(config)

    assert backend.turn_started.wait(timeout=5)  # turn 1's act() is blocked in flight
    assert svc.stop_run(run_id)
    backend.may_proceed.set()  # let turn 1 complete; the loop must not start turn 2

    _await(lambda: svc.get_run(run_id).outcome != "incomplete")
    run = svc.get_run(run_id)
    assert run.outcome == "stopped"
    assert len(run.transcript) == 1


def test_stop_run_on_unknown_id_returns_false(tmp_path):
    svc = _service(tmp_path)
    assert svc.stop_run("no-such-run") is False


def test_stop_campaign_interrupts_the_in_flight_phase_not_just_future_ones(tmp_path, mock_server):
    svc = _service(tmp_path)
    backend = _PausableBackend()
    svc._backend_for = lambda config: backend

    cfg = CampaignConfig(
        domain=mock_server, backend="offline", phase_step_budget=1000,
        opsec_min_interval=0.0, opsec_jitter=0.0,
    )
    cid = svc.start_campaign(cfg)

    # Wait until the phase is genuinely mid-flight (turn 1's act() is blocked) before stopping
    # it — this is the scenario stop_campaign() previously could not actually interrupt.
    assert backend.turn_started.wait(timeout=5)
    phase_run_id = svc._get_campaign_obj(cid).phases[-1]
    assert svc.stop_campaign(cid)  # flips campaign.status synchronously — the phase itself
    # hasn't caught up yet, so wait for its own Run (not campaign.status) to actually finish.
    backend.may_proceed.set()  # let the in-flight turn complete; no further turn must start

    _await(lambda: svc.get_run(phase_run_id).outcome != "incomplete")
    run = svc.get_run(phase_run_id)
    assert run.outcome == "stopped"
    assert len(run.transcript) == 1

    campaign = svc.get_campaign(cid)
    # The post-run_loop coverage/hardened-streak bookkeeping must not clobber "stopped".
    assert campaign["status"] == "stopped"
