"""The HTTP API exposes the knowledge base, vuln search, defense, and i18n."""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from backend.app import make_handler
from backend.pillars import PlatformServices
from backend.service import RunService


# ── service layer ──
def test_platform_services_kb_and_render():
    p = PlatformServices()
    listing = p.kb_list()
    assert listing["total"] >= 20 and listing["categories"]
    doc = p.kb_doc("sql_injection")
    assert doc and "<h2" in doc["html"]
    assert "<script>" not in doc["html"]  # payloads stay escaped through the API
    assert doc["toc"]


def test_platform_services_vuln_and_i18n():
    p = PlatformServices()
    vs = p.vuln_search("sql injection")
    assert vs["techniques"] and vs["techniques"][0]["slug"] == "sql_injection"
    i18n = p.i18n("vi")
    assert i18n["strings"]["nav.defense"] == "Phòng thủ"
    assert "en" in i18n["available"]


def test_defense_review_missing_path():
    p = PlatformServices()
    assert "error" in p.defense_review("/nope/does/not/exist")


def test_defense_review_finds_issues(tmp_path):
    (tmp_path / "app.py").write_text(
        "cursor.execute('SELECT * FROM u WHERE n = ' + name)\n", encoding="utf-8"
    )
    report = PlatformServices().defense_review(str(tmp_path))
    assert report["files_scanned"] == 1
    assert any(f["slug"] == "sql_injection" for f in report["findings"])


# ── HTTP layer ──
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


def _get(url):
    with urlopen(url) as resp:
        assert resp.status == 200
        return json.loads(resp.read())


def test_http_kb_endpoints(api):
    assert _get(f"{api}/kb")["total"] >= 20
    doc = _get(f"{api}/kb/doc/sql_injection")
    assert doc["id"] == "sql_injection" and doc["html"]
    hits = _get(f"{api}/kb/search?q=parameterized")["hits"]
    assert hits


def test_http_kb_doc_404(api):
    with pytest.raises(HTTPError) as exc:
        urlopen(f"{api}/kb/doc/no-such-doc")
    assert exc.value.code == 404


def test_http_vuln_search_and_i18n(api):
    vs = _get(f"{api}/vuln-search?q=ssrf")
    assert vs["techniques"][0]["slug"] == "ssrf"
    assert vs["online"] is False
    assert _get(f"{api}/i18n/vi")["strings"]["nav.defense"] == "Phòng thủ"


def test_http_defense_review(api, tmp_path):
    (tmp_path / "vuln.py").write_text("import os\nos.system('ping ' + host)\n", encoding="utf-8")
    body = json.dumps({"path": str(tmp_path)}).encode()
    with urlopen(Request(f"{api}/defense/review", data=body, method="POST")) as resp:
        report = json.loads(resp.read())
    assert any(f["slug"] == "os_command_injection" for f in report["findings"])


def test_http_defense_review_bad_path(api):
    body = json.dumps({"path": "/does/not/exist/anywhere"}).encode()
    with pytest.raises(HTTPError) as exc:
        urlopen(Request(f"{api}/defense/review", data=body, method="POST"))
    assert exc.value.code == 400
