"""Redaction and tamper-evident evidence persistence."""

import json

from ai_framework.agent.contracts import Run, RunConfig, ToolCall, Turn
from ai_framework.agent.run_store import JsonRunStore
from ai_framework.evidence import EvidenceLedger
from ai_framework.security.redaction import redact_data, redact_text


def test_redaction_handles_headers_nested_keys_and_jwts():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    value = {
        "headers": {"Authorization": "Bearer super-secret", "X-Test": "keep"},
        "password": "hunter2",
        "output": f"token={token}",
    }
    clean = redact_data(value)
    assert clean["headers"]["Authorization"] == "[REDACTED]"
    assert clean["headers"]["X-Test"] == "keep"
    assert clean["password"] == "[REDACTED]"
    assert token not in clean["output"]
    assert "super-secret" not in redact_text("Authorization: Bearer super-secret")


def test_run_store_never_persists_tool_credentials(tmp_path):
    store = JsonRunStore(tmp_path / "runs")
    run = Run(
        config=RunConfig(goal="g", target="http://example.test"),
        transcript=[
            Turn(
                index=0,
                tool_calls=[
                    ToolCall(
                        id="c1",
                        name="set_auth",
                        arguments={"token": "raw-access-token"},
                    )
                ],
            )
        ],
    )
    store.save(run)
    raw = (tmp_path / "runs" / f"{run.id}.json").read_text(encoding="utf-8")
    assert "raw-access-token" not in raw
    assert "[REDACTED]" in raw


def test_evidence_ledger_detects_tampering(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path)
    ledger.append("one", {"result": "ok"})
    ledger.append("two", {"api_key": "do-not-store"})
    assert ledger.verify() == (True, "verified 2 records")
    assert "do-not-store" not in path.read_text(encoding="utf-8")

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["payload"]["result"] = "tampered"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    ok, reason = ledger.verify()
    assert ok is False
    assert "hash mismatch" in reason
