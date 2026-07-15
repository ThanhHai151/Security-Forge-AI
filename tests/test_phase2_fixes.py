"""Regression tests for the Phase 2 durability/correctness fixes (see docs/AGENT_REVIEW)."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from ai_framework.agent.campaign import (
    Campaign,
    CampaignConfig,
    CoverageItem,
    CoverageStatus,
    PendingApproval,
    record_manual_action,
)
from ai_framework.agent.contracts import Budget, RunConfig, ToolCall
from ai_framework.agent.loop import run_loop
from ai_framework.models.base import ActResponse
from ai_framework.supervisor.ingest import _CONFIRMED_RE
from ai_framework.tools.base import ToolRegistry
from ai_framework.tools.session import HttpSession

# ── #8: model-call resilience — retry then a defined error terminus ──────────────────


class _FailingBackend:
    name = "failing"

    def act(self, system, transcript, config, tools):
        raise RuntimeError("provider exploded")

    def plan(self, system, transcript, config):
        return ""


class _FlakyBackend:
    """Fails ``fail_times`` then returns done — exercises the retry path."""

    name = "flaky"

    def __init__(self, fail_times):
        self.fail_times = fail_times
        self.attempts = 0

    def act(self, system, transcript, config, tools):
        self.attempts += 1
        if self.attempts <= self.fail_times:
            raise RuntimeError("transient 503")
        return ActResponse(done=True, reasoning="done", tool_calls=[])

    def plan(self, system, transcript, config):
        return ""


def _cfg():
    return RunConfig(goal="g", target="http://localhost", step_budget=3,
                     authorized_targets={"localhost"})


def test_exhausted_retries_set_error_outcome_and_do_not_raise():
    run = run_loop(
        _cfg(), _FailingBackend(), ToolRegistry(),
        max_model_retries=2, retry_sleep=lambda _s: None,
    )
    assert run.outcome == "error"
    assert "model act failed" in run.error


def test_transient_failure_is_retried_then_succeeds():
    backend = _FlakyBackend(fail_times=2)
    run = run_loop(
        _cfg(), backend, ToolRegistry(),
        max_model_retries=2, retry_sleep=lambda _s: None,
    )
    assert run.outcome == "done"
    assert backend.attempts == 3  # 2 failures + 1 success


# ── #9: plan() is Headroom-fitted (a compaction report is recorded for the plan call) ──


class _OneTurnBackend:
    name = "oneturn"

    def __init__(self):
        self.done_next = False

    def act(self, system, transcript, config, tools):
        done = self.done_next
        self.done_next = True
        return ActResponse(done=done, reasoning="r", tool_calls=[])

    def plan(self, system, transcript, config):
        return "next step"


def test_plan_call_is_fitted_under_budget():
    run = run_loop(
        _cfg(), _OneTurnBackend(), ToolRegistry(),
        budget=Budget(context_window=20_000, reserved_output_headroom=5_000),
        retry_sleep=lambda _s: None,
    )
    # One turn executed: it produces an act-fit report AND a plan-fit report (plan no longer
    # bypasses Headroom), so at least two compaction reports exist for a single completed turn.
    assert len(run.compaction_reports) >= 2


# ── #16: a failed manual action must not downgrade a confirmed technique ──────────────


def test_record_manual_action_does_not_downgrade_confirmed():
    coverage = [CoverageItem(technique="sqli", status=CoverageStatus.confirmed, phase=1)]
    call = ToolCall(id="1", name="http_request", arguments={"body": "' or 1=1 sqli"})
    out = record_manual_action(coverage, call, ok=False, phase=2)
    sqli = next(c for c in out if c.technique == "sqli")
    assert sqli.status == CoverageStatus.confirmed  # not downgraded to "tried"


def test_record_manual_action_still_escalates_on_success():
    coverage = [CoverageItem(technique="sqli", status=CoverageStatus.tried, phase=1)]
    call = ToolCall(id="1", name="http_request", arguments={"body": "' or 1=1 sqli"})
    out = record_manual_action(coverage, call, ok=True, phase=2)
    sqli = next(c for c in out if c.technique == "sqli")
    assert sqli.status == CoverageStatus.confirmed


# ── #15: hyphenated technique names survive the ingest CONFIRMED parser ───────────────


class TestIngestHyphenatedNames:
    def test_hyphenated_names_are_not_truncated(self):
        for name in ["Cross-Site Scripting", "Server-Side Request Forgery", "DOM-based XSS"]:
            m = _CONFIRMED_RE.match(f"CONFIRMED: {name} - clear evidence here")
            assert m is not None
            assert m.group(1).strip() == name
            assert m.group(3).strip() == "clear evidence here"

    def test_severity_bracket_still_parsed(self):
        m = _CONFIRMED_RE.match("CONFIRMED: SSRF [high] - hit metadata endpoint")
        assert m and m.group(1).strip() == "SSRF"
        assert m.group(2) == "high"


# ── #18: durable stores are written owner-only (0600) ────────────────────────────────


class TestStorePermissions:
    def test_finding_store_is_0600(self, tmp_path):
        from ai_framework.notes.contracts import Finding
        from ai_framework.notes.store import JsonlFindingStore

        path = tmp_path / "f.jsonl"
        JsonlFindingStore(path).write(Finding(target="t", title="x"))
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    def test_memory_store_is_0600(self, tmp_path):
        from ai_framework.agent.contracts import MemoryKind, MemoryRecord
        from ai_framework.memory.store import JsonlMemoryStore

        path = tmp_path / "m.jsonl"
        JsonlMemoryStore(path).write(MemoryRecord(id="1", kind=MemoryKind.target_fact))
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


# ── #19: no ambient HTTP(S)_PROXY is honored when no proxy is configured ──────────────


def test_session_ignores_ambient_proxy_env(monkeypatch):
    from urllib.request import ProxyHandler

    monkeypatch.setenv("HTTP_PROXY", "http://evil-proxy.test:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://evil-proxy.test:8080")
    sess = HttpSession()  # no proxy configured
    # The explicit empty ProxyHandler suppresses urllib's default env-reading one, so NO handler
    # in the opener carries the ambient HTTP(S)_PROXY — traffic is never silently routed through it.
    leaking = [
        h for h in sess._opener.handlers
        if isinstance(h, ProxyHandler) and getattr(h, "proxies", {})
    ]
    assert not leaking


def test_session_still_uses_an_explicit_proxy(monkeypatch):
    from urllib.request import ProxyHandler

    monkeypatch.delenv("HTTP_PROXY", raising=False)
    sess = HttpSession(proxy="http://127.0.0.1:8080")
    proxied = [
        h for h in sess._opener.handlers
        if isinstance(h, ProxyHandler) and getattr(h, "proxies", {})
    ]
    assert proxied  # an operator-configured proxy (Burp/pivot) is still honored


# ── #12: approvals expire (single-use + time-boxed) ──────────────────────────────────


def test_expired_approval_is_refused(tmp_path):
    from ai_framework.agent.campaign import ApprovalStatus
    from ai_framework.tools.base import ToolRegistry
    from backend.service import RunService

    class _Tool:
        name = "probe"
        description = "d"
        touches_network = False
        mutating = True

        def __init__(self):
            self.calls = 0

        @property
        def json_schema(self):
            return {"type": "object", "properties": {}}

        def run(self, args, ctx):
            self.calls += 1
            return "ran"

    tool = _Tool()
    registry = ToolRegistry()
    registry.register(tool)
    service = RunService(
        registry=registry, memory_path=None, findings_path=None, runs_dir=None,
        campaigns_dir=str(tmp_path / "c"), assets_path=None,
        notebook_dir=str(tmp_path / "nb"), evidence_path=str(tmp_path / "e.jsonl"),
    )
    campaign = Campaign(config=CampaignConfig(domain="http://localhost"))
    approval = PendingApproval(
        phase=1, tool_call=ToolCall(id="c1", name="probe", arguments={}),
        created_at=datetime.now(UTC) - timedelta(hours=2),  # older than the default window
    )
    campaign.pending_approvals.append(approval)
    service._campaigns[campaign.id] = campaign

    assert service.approve_action(campaign.id, approval.id) is False
    assert approval.status == ApprovalStatus.expired
    assert tool.calls == 0  # the stale action never executed


# ── #25: asset store tolerates a truncated/corrupt line ──────────────────────────────


def test_asset_store_skips_a_corrupt_line(tmp_path):
    from ai_framework.agent.assets import Asset, JsonlAssetStore

    path = tmp_path / "a.jsonl"
    store = JsonlAssetStore(path)
    store.write(Asset(target="t", kind="host", value="a.example"))
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"broken": ')  # truncated final line (simulated crash mid-append)
    assets = store.all()  # must not raise
    assert len(assets) == 1 and assets[0].value == "a.example"


# ── #10: boot-time reconcile of an orphaned "running" campaign ────────────────────────


def test_reconcile_marks_orphaned_running_campaign_interrupted(tmp_path):
    from ai_framework.agent.campaign import Campaign, CampaignStatus, CampaignStore

    store = CampaignStore(tmp_path / "camp")
    campaign = Campaign(config=CampaignConfig(domain="http://localhost"))
    campaign.status = CampaignStatus.running  # simulate a crash while a phase was executing
    store.save(campaign)

    reconciled = store.reconcile_interrupted()
    assert campaign.id in reconciled
    reloaded = store.load(campaign.id)
    assert reloaded.status == CampaignStatus.interrupted


def test_reconcile_survives_a_corrupt_campaign_file(tmp_path):
    # A schema-drifted/corrupt "running" file must be skipped, not crash boot (RunService.__init__).
    from ai_framework.agent.campaign import CampaignStore

    d = tmp_path / "camp"
    d.mkdir()
    (d / "bad.json").write_text('{"status": "running", "config": {"nope": true}}', encoding="utf-8")
    (d / "broken.json").write_text("{not json", encoding="utf-8")
    reconciled = CampaignStore(d).reconcile_interrupted()  # must not raise
    assert reconciled == []
