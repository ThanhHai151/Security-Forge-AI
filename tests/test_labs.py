"""Labs: faithful-but-sandboxed exploits, registry, reset, and server containment."""

from __future__ import annotations

import json
import threading
from urllib.request import Request, urlopen

import pytest

from labs.base import LabRequest
from labs.builtin import IdorLab, ReflectedXssLab, SqliLoginBypassLab, eval_predicate
from labs.registry import default_registry
from labs.server import LABS_HOST, build_labs_server, labs_enabled


# ── the toy SQL evaluator behaves like a vulnerable WHERE clause ──
def test_eval_predicate_legit_match():
    row = {"username": "wiener", "password": "peter"}
    assert eval_predicate("username = 'wiener' AND password = 'peter'", row) is True
    assert eval_predicate("username = 'wiener' AND password = 'wrong'", row) is False


def test_eval_predicate_comment_bypass():
    row = {"username": "administrator", "password": "s3cr3t"}
    # administrator'--  → password check commented out
    assert eval_predicate("username = 'administrator'-- ' AND password = 'x'", row) is True


def test_eval_predicate_tautology_bypass():
    row = {"username": "administrator", "password": "s3cr3t"}
    assert eval_predicate("username = '' OR '1'='1'-- ' AND password = 'x'", row) is True


# ── SQLi login bypass lab ──
def test_sqli_lab_rejects_bad_creds():
    lab = SqliLoginBypassLab()
    req = LabRequest(method="POST", path="/login", body={"username": "x", "password": "y"})
    resp = lab.handle(req)
    assert resp.status == 401 and not lab.solved


def test_sqli_lab_valid_login_is_not_a_solve():
    lab = SqliLoginBypassLab()
    resp = lab.handle(
        LabRequest(method="POST", path="/login", body={"username": "wiener", "password": "peter"})
    )
    assert resp.status == 200 and resp.solved is False  # logged in legitimately


def test_sqli_lab_injection_solves():
    lab = SqliLoginBypassLab()
    req = LabRequest(
        method="POST", path="/login", body={"username": "administrator'--", "password": "x"}
    )
    resp = lab.handle(req)
    assert resp.solved is True and lab.solved is True
    assert "administrator" in resp.body.lower()


# ── reflected XSS lab ──
def test_xss_lab_reflects_and_solves():
    lab = ReflectedXssLab()
    resp = lab.handle(LabRequest(path="/search", query={"q": "<script>alert(1)</script>"}))
    assert "<script>alert(1)</script>" in resp.body  # reflected verbatim (the bug)
    assert resp.solved is True


def test_xss_lab_benign_query_not_solved():
    lab = ReflectedXssLab()
    resp = lab.handle(LabRequest(path="/search", query={"q": "hello"}))
    assert resp.solved is False


# ── IDOR lab ──
def test_idor_lab_own_account_not_solved():
    lab = IdorLab()
    resp = lab.handle(LabRequest(path="/account", query={"id": "1"}))
    assert resp.solved is False and "wiener" in resp.body


def test_idor_lab_other_account_solves():
    lab = IdorLab()
    resp = lab.handle(LabRequest(path="/account", query={"id": "2"}))
    assert resp.solved is True and "administrator" in resp.body


# ── registry + reset ──
def test_registry_lists_and_resets():
    reg = default_registry()
    metas = reg.list()
    assert {m.slug for m in metas} >= {"sqli-login-bypass", "reflected-xss", "idor"}
    assert all(m.kb_id for m in metas)  # each links to a KB class

    reg.handle("idor", LabRequest(path="/account", query={"id": "2"}))
    assert reg.get("idor").solved is True
    assert reg.reset("idor") is True
    assert reg.get("idor").solved is False
    assert reg.reset("nope") is False


# ── server containment ──
def test_server_disabled_by_default():
    with pytest.raises(RuntimeError, match="disabled by default"):
        build_labs_server(enabled=False)


def test_labs_enabled_resolution(monkeypatch):
    monkeypatch.delenv("SECFORGE_LABS_ENABLED", raising=False)
    assert labs_enabled() is False
    monkeypatch.setenv("SECFORGE_LABS_ENABLED", "1")
    assert labs_enabled() is True
    assert labs_enabled(False) is False  # explicit flag overrides env


@pytest.fixture
def labs_server():
    server = build_labs_server(port=0, enabled=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    assert host == "127.0.0.1"  # bound to localhost only
    try:
        yield f"http://{LABS_HOST}:{port}"
    finally:
        server.shutdown()
        thread.join()


def test_server_lists_and_runs_a_lab(labs_server):
    with urlopen(f"{labs_server}/labs") as resp:
        labs = json.loads(resp.read())
    assert any(la["slug"] == "idor" for la in labs)

    with urlopen(f"{labs_server}/labs/idor?id=2") as resp:
        assert resp.headers.get("X-Lab-Solved") == "1"
        assert b"administrator" in resp.read()

    # reset clears the solve
    with urlopen(Request(f"{labs_server}/labs/idor/reset", data=b"", method="POST")) as resp:
        assert json.loads(resp.read())["reset"] is True
    with urlopen(f"{labs_server}/labs/idor?id=1") as resp:
        assert resp.headers.get("X-Lab-Solved") == "0"
