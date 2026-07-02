"""Shared fixtures: a localhost HTTP server so http_get is testable without the network."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello from mock target")

    def log_message(self, *args: object) -> None:  # silence test output
        pass


@pytest.fixture(autouse=True)
def _isolate_usage_store(tmp_path, monkeypatch) -> None:
    """Point the default UsageStore path at a temp file for every test.

    The RouterBackend persists per-account usage on each model call; when a test builds one
    without injecting a UsageStore it would otherwise write ai_usage.json into the repo root.
    """
    monkeypatch.setenv("SECFORGE_USAGE", str(tmp_path / "ai_usage.json"))


@pytest.fixture
def mock_server() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join()
