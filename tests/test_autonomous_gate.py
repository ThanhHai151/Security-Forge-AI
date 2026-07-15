"""SecForge no longer executes pentest actions by default (see ``AutonomousDisabledError`` in
``backend/service.py``). Existing tests opt back in via the autouse fixture in ``conftest.py``;
this file explicitly verifies the off-by-default gate itself.
"""

import json
import threading
from http.server import HTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ai_framework.agent.campaign import CampaignConfig
from ai_framework.agent.contracts import RunConfig
from backend.app import make_handler
from backend.service import AutonomousDisabledError, RunService


def _service(tmp_path) -> RunService:
    return RunService(
        memory_path=str(tmp_path / "m.jsonl"),
        findings_path=str(tmp_path / "f.jsonl"),
        runs_dir=str(tmp_path / "runs"),
        campaigns_dir=str(tmp_path / "camp"),
        notebook_dir=str(tmp_path / "nb"),
        archetype_path=str(tmp_path / "arch.json"),
    )


def test_start_run_raises_when_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("SECFORGE_ENABLE_AUTONOMOUS", raising=False)
    svc = _service(tmp_path)
    with pytest.raises(AutonomousDisabledError):
        svc.start_run(RunConfig(goal="g", target="http://x"))


def test_start_campaign_raises_when_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("SECFORGE_ENABLE_AUTONOMOUS", raising=False)
    svc = _service(tmp_path)
    with pytest.raises(AutonomousDisabledError):
        svc.start_campaign(CampaignConfig(domain="http://x"))


def test_start_run_works_when_explicitly_enabled(tmp_path, monkeypatch, mock_server):
    monkeypatch.setenv("SECFORGE_ENABLE_AUTONOMOUS", "1")
    svc = _service(tmp_path)
    run_id = svc.start_run(
        RunConfig(goal="recon", target=mock_server, authorized_targets={mock_server})
    )
    assert run_id


def test_http_runs_endpoint_returns_403_when_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("SECFORGE_ENABLE_AUTONOMOUS", raising=False)
    service = _service(tmp_path)
    server = HTTPServer(("127.0.0.1", 0), make_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        body = json.dumps({"goal": "g", "target": "http://x"}).encode()
        with pytest.raises(HTTPError) as exc_info:
            urlopen(
                Request(
                    f"http://{host}:{port}/runs",
                    data=body,
                    method="POST",
                    headers={"Content-Type": "application/json", "X-SecForge-Client": "test"},
                )
            )
        assert exc_info.value.code == 403
    finally:
        server.shutdown()
        thread.join()


def test_supervisor_advise_works_regardless_of_the_gate(tmp_path, monkeypatch):
    monkeypatch.delenv("SECFORGE_ENABLE_AUTONOMOUS", raising=False)
    svc = _service(tmp_path)
    advice = svc.advise("example.test.com", "sql injection")
    assert advice["plan"]
