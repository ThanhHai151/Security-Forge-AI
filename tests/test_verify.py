"""FindingVerifier: replay logic (marker / status / off-scope) + report surfacing."""

from ai_framework.agent.verify import FindingVerifier
from ai_framework.notes.contracts import Finding, Severity
from ai_framework.notes.report import render_markdown
from ai_framework.tools.base import ToolContext


class _Resp:
    def __init__(self, status, body):
        self.status = status
        self._b = body.encode()

    def read(self, _n=None):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _StubSession:
    """Duck-typed opener returning a canned response, recording the last request."""

    def __init__(self, status, body):
        self._r = _Resp(status, body)
        self.last = None

    def open(self, req, timeout):
        self.last = req
        return self._r


def _ctx(status, body, targets=("example.com",)):
    return ToolContext(authorized_targets=set(targets), session=_StubSession(status, body))


V = FindingVerifier()


def test_marker_present_confirms():
    ok, note = V.verify(
        {"request": {"url": "http://example.com/etc"}, "expect": "root:x:0:0"},
        _ctx(200, "root:x:0:0:root:/root"),
    )
    assert ok and "found" in note and "confirmed" in note


def test_marker_absent_denies():
    ok, note = V.verify(
        {"request": {"url": "http://example.com/etc"}, "expect": "root:x:0:0"},
        _ctx(200, "nothing here"),
    )
    assert not ok and "ABSENT" in note and "NOT reproduced" in note


def test_status_expectation():
    ok, _ = V.verify(
        {"request": {"url": "http://example.com/admin"}, "expect_status": 200}, _ctx(200, "")
    )
    assert ok
    ok2, _ = V.verify(
        {"request": {"url": "http://example.com/admin"}, "expect_status": 200}, _ctx(403, "")
    )
    assert not ok2


def test_combined_marker_and_status_both_must_hold():
    repro = {"request": {"url": "http://example.com/x"}, "expect": "ADMIN", "expect_status": 200}
    assert V.verify(repro, _ctx(200, "welcome ADMIN"))[0] is True
    assert V.verify(repro, _ctx(200, "guest"))[0] is False  # marker missing
    assert V.verify(repro, _ctx(500, "ADMIN"))[0] is False  # status wrong


def test_off_scope_repro_is_refused():
    ok, note = V.verify(
        {"request": {"url": "http://evil.com/x"}, "expect": "x"}, _ctx(200, "x", targets=())
    )
    assert not ok and "off-scope" in note


def test_missing_url_is_unverified():
    ok, note = V.verify({"expect": "x"}, _ctx(200, "x"))
    assert not ok and "no request.url" in note


def test_no_expectation_uses_2xx_as_weak_confirmation():
    assert V.verify({"request": {"url": "http://example.com/"}}, _ctx(204, ""))[0] is True
    assert V.verify({"request": {"url": "http://example.com/"}}, _ctx(404, ""))[0] is False


def test_report_shows_verified_and_unverified_badges():
    findings = [
        Finding(title="Confirmed SQLi", severity=Severity.critical, verified=True,
                verification="replayed GET … confirmed"),
        Finding(title="Maybe XSS", severity=Severity.medium, verified=False),
    ]
    md = render_markdown(findings, target="example.com")
    assert "✅ verified" in md and "⚠️ unverified" in md
    assert "replayed GET … confirmed" in md
