"""Every HTTP verb answers JSON even when a handler raises unexpectedly.

Regression coverage for a real incident: an uncaught exception in a GET handler produced the
stdlib http.server's bare (non-JSON) error page, which broke the frontend's error-message
parsing and made the whole Providers page look like it had lost every connection when only one
endpoint's response body wasn't JSON.
"""

import json
import threading
from http.server import HTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from ai_framework.router.accounts import AccountStore
from backend.app import make_handler
from backend.service import RunService


@pytest.fixture
def api(tmp_path):
    accounts = AccountStore(path=str(tmp_path / "accounts.json"))
    service = RunService(memory_path=str(tmp_path / "mem.jsonl"), accounts=accounts)
    server = HTTPServer(("127.0.0.1", 0), make_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://127.0.0.1:{port}", service
    finally:
        server.shutdown()
        thread.join()


def test_get_handler_exception_still_answers_json_not_a_raw_error_page(api, monkeypatch):
    base, service = api

    def boom():
        raise RuntimeError("simulated crash reading the account pool")

    monkeypatch.setattr(service.accounts, "get_policy", boom)

    with pytest.raises(HTTPError) as exc:
        urlopen(f"{base}/accounts")
    assert exc.value.code == 500
    body = json.loads(exc.value.read())  # must parse as JSON, not a bare html/text error page
    assert "simulated crash" in body["error"]
