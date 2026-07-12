"""The local control-plane API fails closed when exposure or secret export is requested."""

import json
import threading
from http.server import HTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from backend.app import build_server, make_handler
from backend.service import RunService


def test_non_loopback_binding_requires_api_token(tmp_path, monkeypatch):
    monkeypatch.delenv("SECFORGE_API_TOKEN", raising=False)
    service = RunService(memory_path=str(tmp_path / "memory.jsonl"))
    with pytest.raises(RuntimeError, match="requires SECFORGE_API_TOKEN"):
        build_server(service, "0.0.0.0", 0)


def test_configured_api_token_is_required(tmp_path):
    service = RunService(memory_path=str(tmp_path / "memory.jsonl"))
    server = HTTPServer(("127.0.0.1", 0), make_handler(service, api_token="control-secret"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/accounts"
    try:
        with pytest.raises(HTTPError) as missing:
            urlopen(url)
        assert missing.value.code == 401

        request = Request(url, headers={"Authorization": "Bearer control-secret"})
        with urlopen(request) as response:
            assert response.status == 200
            assert "accounts" in json.loads(response.read())
    finally:
        server.shutdown()
        thread.join()


def test_loopback_api_rejects_untrusted_host_header(tmp_path):
    service = RunService(memory_path=str(tmp_path / "memory.jsonl"))
    server = HTTPServer(("127.0.0.1", 0), make_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/accounts"
    try:
        request = Request(url, headers={"Host": "attacker.example"})
        with pytest.raises(HTTPError) as rejected:
            urlopen(request)
        assert rejected.value.code == 403
    finally:
        server.shutdown()
        thread.join()
