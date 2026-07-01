"""Defense: signature scan, secure-guidance mapping, prioritization, re-check."""

from __future__ import annotations

from defense.review import recheck, review_path
from defense.signatures import default_signatures

VULN_PY = '''\
import os
import sqlite3
import pickle


def login(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)  # sqli


def ping(host):
    os.system("ping " + host)  # command injection


def load(blob):
    return pickle.loads(blob)  # insecure deserialization


API_KEY = "sk-supersecretvalue123"  # hardcoded secret
'''

CLEAN_PY = '''\
def login(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))


def ping(host):
    import subprocess
    subprocess.run(["ping", host], check=True)
'''


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_signature_set_maps_to_catalog_slugs():
    slugs = {s.slug for s in default_signatures()}
    # Every signature targets a real catalog class.
    from vuln_search.catalog import load_catalog

    catalog_slugs = {c.slug for c in load_catalog()}
    assert slugs <= catalog_slugs, slugs - catalog_slugs


def test_review_finds_vulnerable_patterns(tmp_path):
    _write(tmp_path, "app.py", VULN_PY)
    report = review_path(tmp_path)
    found = {f.slug for f in report.findings}
    assert {"sql_injection", "os_command_injection", "insecure_deserialization"} <= found
    assert "broken_authentication" in found  # hardcoded secret
    assert report.files_scanned == 1


def test_findings_carry_secure_guidance(tmp_path):
    _write(tmp_path, "app.py", VULN_PY)
    report = review_path(tmp_path)
    sqli = next(f for f in report.findings if f.slug == "sql_injection")
    assert sqli.title  # resolved from the catalog
    assert "parameter" in sqli.guidance.lower()  # pulled from the card's "Defenses" section


def test_findings_are_prioritized_by_severity(tmp_path):
    _write(tmp_path, "app.py", VULN_PY)
    report = review_path(tmp_path)
    ranks = ["critical", "high", "medium", "low"]
    seen = [ranks.index(f.severity) for f in report.findings]
    assert seen == sorted(seen)  # critical first
    assert report.by_severity.get("critical", 0) >= 1


def test_clean_code_yields_no_findings(tmp_path):
    _write(tmp_path, "safe.py", CLEAN_PY)
    report = review_path(tmp_path)
    assert report.findings == []
    assert "no catalogued weaknesses" in report.summary


def test_skips_non_source_and_vendored_dirs(tmp_path):
    _write(tmp_path, "node_modules/evil/index.js", "eval(userInput)")
    _write(tmp_path, "data.bin", "pickle.loads(x)")  # non-text ext
    report = review_path(tmp_path)
    assert report.findings == []


def test_recheck_confirms_and_clears(tmp_path):
    p = _write(tmp_path, "app.py", VULN_PY)
    report = review_path(tmp_path)
    sqli = next(f for f in report.findings if f.slug == "sql_injection")
    assert recheck(sqli, tmp_path) is True
    # After remediation the same line no longer matches.
    p.write_text(CLEAN_PY, encoding="utf-8")
    assert recheck(sqli, tmp_path) is False


def test_review_single_file(tmp_path):
    p = _write(tmp_path, "app.py", VULN_PY)
    report = review_path(p)
    assert report.files_scanned == 1 and report.findings
    assert all(f.file == "app.py" for f in report.findings)
