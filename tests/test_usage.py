"""UsageStore (the Quota Tracker's data) + token capture through the RouterBackend.

Covers: per-account accumulation into a lifetime total and per-day buckets, day-bucket trimming,
reset, the OpenAI/Anthropic ``usage`` normalizer, and the router recording tokens on success and
counting a call on failure — all without touching the network (``http_post`` is injected).
"""

import pytest

from ai_framework.agent.contracts import RunConfig
from ai_framework.models.base import normalize_usage
from ai_framework.models.openai_compat import HttpError
from ai_framework.router.accounts import Account, AccountStore
from ai_framework.router.router import RouterBackend
from ai_framework.router.usage import _RETAIN_DAYS, UsageStore


def _config():
    return RunConfig(goal="probe", target="example.test")


# ── UsageStore ──
def test_record_accumulates_lifetime_total_and_today(tmp_path):
    store = UsageStore(path=str(tmp_path / "u.json"))
    store.record("acc1", ok=True, prompt_tokens=10, completion_tokens=5, total_tokens=15)
    store.record("acc1", ok=True, prompt_tokens=2, completion_tokens=3)  # total derived → 5

    snap = store.snapshot()["acc1"]
    assert snap["total"]["calls"] == 2
    assert snap["total"]["ok"] == 2
    assert snap["total"]["total_tokens"] == 20  # 15 + (2+3)
    assert snap["today"]["prompt_tokens"] == 12
    assert snap["today"]["calls"] == 2


def test_record_counts_failures_separately(tmp_path):
    store = UsageStore(path=str(tmp_path / "u.json"))
    store.record("acc1", ok=True)
    store.record("acc1", ok=False)

    total = store.snapshot()["acc1"]["total"]
    assert total["calls"] == 2
    assert total["ok"] == 1
    assert total["fail"] == 1


def test_day_buckets_are_trimmed_to_the_retention_window(tmp_path):
    store = UsageStore(path=str(tmp_path / "u.json"))
    for i in range(_RETAIN_DAYS + 5):  # more days than we retain
        store.record("acc1", ok=True, day=f"2026-{(i // 28) + 1:02d}-{(i % 28) + 1:02d}")

    days = store.snapshot()["acc1"]["days"]
    assert len(days) == _RETAIN_DAYS  # oldest buckets dropped, lifetime total is unaffected
    assert store.snapshot()["acc1"]["total"]["calls"] == _RETAIN_DAYS + 5


def test_reset_one_account_leaves_others(tmp_path):
    store = UsageStore(path=str(tmp_path / "u.json"))
    store.record("a", ok=True)
    store.record("b", ok=True)

    store.reset("a")
    snap = store.snapshot()
    assert "a" not in snap
    assert "b" in snap


def test_reset_all_clears_the_store(tmp_path):
    store = UsageStore(path=str(tmp_path / "u.json"))
    store.record("a", ok=True)

    store.reset()
    assert store.snapshot() == {}


def test_snapshot_of_a_missing_file_is_empty(tmp_path):
    assert UsageStore(path=str(tmp_path / "nope.json")).snapshot() == {}


# ── normalize_usage ──
def test_normalize_openai_usage_reads_prompt_completion_total():
    u = normalize_usage({"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10})
    assert u == {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}


def test_normalize_openai_usage_derives_total_when_absent():
    u = normalize_usage({"prompt_tokens": 7, "completion_tokens": 3})
    assert u["total_tokens"] == 10


def test_normalize_anthropic_usage_maps_input_output_tokens():
    u = normalize_usage({"input_tokens": 12, "output_tokens": 4}, anthropic=True)
    assert u == {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16}


def test_normalize_usage_returns_none_without_a_usage_block():
    assert normalize_usage(None) is None
    assert normalize_usage("nonsense") is None


# ── router → usage integration ──
def test_router_records_token_usage_on_success(tmp_path):
    store = AccountStore(path=str(tmp_path / "a.json"))
    acct = store.add(Account(label="oai", base_url="https://api.openai.com/v1",
                             api_key="sk", model="gpt-4o-mini"))
    usage = UsageStore(path=str(tmp_path / "u.json"))

    def http_post(url, payload, headers):
        return {"choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}

    RouterBackend(store, http_post=http_post, usage=usage).plan("sys", [], _config())

    snap = usage.snapshot()[acct.id]
    assert snap["total"]["calls"] == 1
    assert snap["total"]["ok"] == 1
    assert snap["total"]["total_tokens"] == 15
    assert snap["today"]["prompt_tokens"] == 10


def test_router_records_a_failed_call_against_the_account(tmp_path):
    store = AccountStore(path=str(tmp_path / "a.json"))
    acct = store.add(Account(label="oai", base_url="https://api.openai.com/v1", api_key="sk"))
    usage = UsageStore(path=str(tmp_path / "u.json"))

    def http_post(url, payload, headers):
        raise HttpError(429, "rate limited")

    with pytest.raises(RuntimeError):  # the only account failed → the run raises
        RouterBackend(store, http_post=http_post, usage=usage).plan("sys", [], _config())

    total = usage.snapshot()[acct.id]["total"]
    assert total["calls"] == 1
    assert total["fail"] == 1
    assert total["total_tokens"] == 0  # a failed call spends no tokens
