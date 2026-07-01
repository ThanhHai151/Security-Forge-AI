"""The continuous campaign layer: chaining phases, coverage, hardening, and the approval gate."""

from __future__ import annotations

import time

from ai_framework.agent.campaign import (
    ApprovalStatus,
    Campaign,
    CampaignConfig,
    CampaignStatus,
    CoverageStatus,
    PendingApproval,
    derive_coverage,
    record_manual_action,
)
from ai_framework.agent.contracts import Run, RunConfig, ToolCall, ToolResult, Turn
from backend.service import RunService


def _service(tmp_path) -> RunService:
    d = tmp_path
    return RunService(
        memory_path=str(d / "m.jsonl"),
        findings_path=str(d / "f.jsonl"),
        runs_dir=str(d / "runs"),
        campaigns_dir=str(d / "camp"),
    )


def _await_phase(svc: RunService, cid: str, timeout: float = 8.0) -> dict:
    """Block until the campaign leaves the ``running`` state (a phase finished)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        c = svc.get_campaign(cid)
        if c and c["status"] != "running":
            return c
        time.sleep(0.05)
    raise AssertionError("phase did not finish in time")


def test_campaign_chains_phases_and_hardens(tmp_path, mock_server):
    svc = _service(tmp_path)
    cfg = CampaignConfig(
        domain=mock_server, backend="offline", phase_step_budget=4,
        opsec_min_interval=0.0, opsec_jitter=0.0,  # keep the test instant
    )
    cid = svc.start_campaign(cfg)

    c = _await_phase(svc, cid)
    assert c["status"] == "awaiting_user"
    assert len(c["phase_runs"]) == 1
    # Recon was exercised and produced a finding → confirmed in the coverage map.
    cov = {x["technique"]: x["status"] for x in c["coverage"]}
    assert cov.get("recon") == "confirmed"

    # Chain further phases; with the offline stub nothing new surfaces, so it hardens.
    hardened = False
    for _ in range(4):
        assert svc.continue_campaign(cid)
        c = _await_phase(svc, cid)
        assert len(c["phase_runs"]) >= 2
        if c["status"] == "hardened":
            hardened = True
            break
    assert hardened, "consecutive empty phases should mark the target hardened"

    # Stop ends it, and continue is refused afterwards.
    assert svc.stop_campaign(cid)
    assert svc.get_campaign(cid)["status"] == "stopped"
    assert not svc.continue_campaign(cid)


def test_approve_action_executes_held_call(tmp_path, mock_server):
    svc = _service(tmp_path)
    cfg = CampaignConfig(domain=mock_server, backend="offline", opsec_min_interval=0.0)
    campaign = Campaign(config=cfg, status=CampaignStatus.awaiting_user)
    # A held read action (http_get to the in-scope mock target) awaiting approval.
    approval = PendingApproval(
        phase=1,
        tool_call=ToolCall(id="c1", name="http_get", arguments={"url": mock_server}),
        rationale="probe the target",
    )
    campaign.pending_approvals.append(approval)
    svc._save_campaign(campaign)  # noqa: SLF001 - test drives the store directly

    assert svc.approve_action(campaign.id, approval.id)
    got = svc.get_campaign(campaign.id)
    pa = got["pending_approvals"][0]
    assert pa["status"] == "approved"
    assert "HTTP 200" in pa["result_log"]

    # Approving an unknown id is a no-op.
    assert not svc.approve_action(campaign.id, "nope")


def test_reject_action(tmp_path, mock_server):
    svc = _service(tmp_path)
    campaign = Campaign(
        config=CampaignConfig(domain=mock_server), status=CampaignStatus.awaiting_user
    )
    approval = PendingApproval(
        phase=1, tool_call=ToolCall(id="c1", name="http_request", arguments={"url": mock_server})
    )
    campaign.pending_approvals.append(approval)
    svc._save_campaign(campaign)  # noqa: SLF001

    assert svc.reject_action(campaign.id, approval.id)
    assert svc.get_campaign(campaign.id)["pending_approvals"][0]["status"] == "rejected"


# ── pure logic ────────────────────────────────────────────────────────────────────


def _run_with(turns: list[Turn]) -> Run:
    return Run(config=RunConfig(goal="g", target="http://127.0.0.1"), transcript=turns)


def test_derive_coverage_marks_tried_confirmed_and_untried():
    turns = [
        Turn(
            index=0,
            reasoning="Recon first, then I will try SQL injection on the login form.",
            tool_calls=[ToolCall(id="a", name="http_get", arguments={"url": "http://127.0.0.1"})],
            tool_results=[ToolResult(call_id="a", log="HTTP 200", ok=True)],
            next_plan="Probe for SQL injection next.",
        ),
        Turn(
            index=1,
            tool_calls=[
                ToolCall(
                    id="b", name="note_finding",
                    arguments={"title": "XSS reflected", "tags": ["xss"]},
                )
            ],
            tool_results=[ToolResult(call_id="b", log="FINDING", ok=True)],
        ),
    ]
    cov = {c.technique: c.status for c in derive_coverage(_run_with(turns), [], 1)}
    assert cov["recon"] == CoverageStatus.tried  # exercised by http_get
    assert cov["xss"] == CoverageStatus.confirmed  # recorded as a finding
    assert cov["sqli"] == CoverageStatus.untried  # named in a plan, not yet tried


def test_derive_coverage_marks_held_action_blocked():
    turns = [
        Turn(
            index=0,
            tool_calls=[
                ToolCall(
                    id="a", name="http_request",
                    arguments={"url": "http://x/login", "method": "POST"},
                )
            ],
            tool_results=[
                ToolResult(call_id="a", log="held for manual approval (http_request ...)", ok=False)
            ],
        )
    ]
    cov = {c.technique: c.status for c in derive_coverage(_run_with(turns), [], 1)}
    assert CoverageStatus.blocked in cov.values()


def test_record_manual_action_confirms_on_success():
    cov = record_manual_action(
        [],
        ToolCall(id="a", name="http_request", arguments={"url": "http://x/?q=' OR 1=1--"}),
        ok=True,
        phase=2,
    )
    assert any(c.status == CoverageStatus.confirmed for c in cov)
    assert any(c.technique == "sqli" for c in cov)


def test_approval_status_enum_roundtrip():
    pa = PendingApproval(phase=1, tool_call=ToolCall(id="a", name="x"))
    assert pa.status == ApprovalStatus.pending
    assert PendingApproval.model_validate_json(pa.model_dump_json()) == pa
