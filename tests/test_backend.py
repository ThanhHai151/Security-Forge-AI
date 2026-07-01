"""Step 9: RunService and the HTTP API expose a run end to end."""

import json
import threading
import time
from http.server import HTTPServer
from urllib.request import Request, urlopen

import pytest

from ai_framework.agent.contracts import Run, RunConfig
from backend.app import make_handler
from backend.service import RunService


def _await_outcome(get, timeout=10.0):
    """Runs are async (background thread); poll until one leaves the 'incomplete' state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = get()
        if run is not None and run.outcome != "incomplete":
            return run
        time.sleep(0.02)
    raise AssertionError("run did not finish in time")


def test_service_starts_and_fetches_run(tmp_path, mock_server):
    service = RunService(memory_path=str(tmp_path / "mem.jsonl"))
    config = RunConfig(goal="recon", target=mock_server, authorized_targets={mock_server})
    run_id = service.start_run(config)

    run = _await_outcome(lambda: service.get_run(run_id))
    assert isinstance(run, Run)
    assert run.outcome == "done"
    assert service.get_run("nope") is None


@pytest.fixture
def api(tmp_path):
    service = RunService(memory_path=str(tmp_path / "mem.jsonl"))
    server = HTTPServer(("127.0.0.1", 0), make_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join()


def test_http_post_and_get_run(api, mock_server):
    body = json.dumps({"goal": "recon", "target": mock_server,
                       "authorized_targets": [mock_server]}).encode()
    with urlopen(Request(f"{api}/runs", data=body, method="POST")) as resp:
        assert resp.status == 201
        run_id = json.loads(resp.read())["id"]

    def fetch():
        with urlopen(f"{api}/runs/{run_id}") as resp:
            assert resp.status == 200
            return Run.model_validate_json(resp.read())

    run = _await_outcome(fetch)
    assert run.outcome == "done"
    assert len(run.transcript) >= 2


def test_http_unknown_run_is_404(api):
    import urllib.error

    with pytest.raises(urllib.error.HTTPError) as exc:
        urlopen(f"{api}/runs/does-not-exist")
    assert exc.value.code == 404
