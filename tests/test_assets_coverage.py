"""Asset graph store + record_asset tool + loop persistence, and extended technique tagging."""

from ai_framework.agent.assets import Asset, JsonlAssetStore
from ai_framework.agent.campaign import _scan_techniques
from ai_framework.agent.contracts import RunConfig, ToolCall
from ai_framework.agent.loop import _record_assets
from ai_framework.tools.base import ToolContext
from ai_framework.tools.builtin import RecordAssetTool


# ── asset store ──
def test_asset_store_roundtrip_and_summary(tmp_path):
    store = JsonlAssetStore(tmp_path / "assets.jsonl")
    store.write(Asset(target="t", kind="endpoint", value="/admin"))
    store.write(Asset(target="t", kind="endpoint", value="/admin"))  # dup value
    store.write(Asset(target="t", kind="param", value="id"))
    store.write(Asset(target="other", kind="tech", value="nginx"))

    s = store.summary("t")
    assert s["total"] == 3
    assert s["by_kind"] == {"endpoint": 2, "param": 1}
    assert s["values"]["endpoint"] == ["/admin"]  # deduped
    assert set(store.summary()["targets"]) == {"t", "other"}


def test_asset_kind_is_normalized():
    assert Asset.normalize_kind("ENDPOINT") == "endpoint"
    assert Asset.normalize_kind("bogus") == "other"
    assert Asset.normalize_kind(None) == "other"


# ── record_asset tool + loop persistence ──
def test_record_asset_tool_single_and_many():
    tool = RecordAssetTool()
    assert "endpoint:/x" in tool.run({"kind": "endpoint", "value": "/x"}, ToolContext())
    out = tool.run({"assets": [{"kind": "param", "value": "q"}, {"kind": "tech", "value": "php"}]},
                   ToolContext())
    assert "param:q" in out and "tech:php" in out


def test_record_asset_tool_empty_is_noop():
    assert "no asset recorded" in RecordAssetTool().run({}, ToolContext())


def test_loop_helper_persists_recorded_assets(tmp_path):
    store = JsonlAssetStore(tmp_path / "a.jsonl")
    config = RunConfig(goal="g", target="http://t.example")
    call = ToolCall(id="c1", name="record_asset",
                    arguments={"assets": [{"kind": "endpoint", "value": "/login"},
                                          {"kind": "param", "value": "next"},
                                          {"value": ""}]})  # blank skipped
    _record_assets(store, config, 3, call)
    assets = store.all()
    assert {a.value for a in assets} == {"/login", "next"}
    assert all(a.target == "http://t.example" and a.source == "step 3" for a in assets)


# ── extended technique tagging for the new tools/skills ──
def test_new_tools_tag_the_right_techniques():
    assert "jwt" in _scan_techniques('run jwt_attack op crack-hs256')
    assert "content-discovery" in _scan_techniques('{"tool": "gobuster"}')
    assert "vuln-scan" in _scan_techniques('{"tool": "nuclei"}')
    assert "command-injection" in _scan_techniques("try os command injection rce")
    assert "sqli" in _scan_techniques('{"tool": "sqlmap", "target": "x"}')
