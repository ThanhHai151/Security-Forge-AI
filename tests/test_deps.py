"""SCA: manifest parsing (pure) and the advisory-scan pipeline (injected source, no network)."""

from __future__ import annotations

from defense.deps import (
    Advisory,
    Dependency,
    parse_dependencies,
    scan_dependencies,
)


def test_parse_requirements_pinned_and_loose(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment\nDjango==3.2.0\nrequests>=2.20\n-r other.txt\nflask[async]==2.0.1\n"
        "git+https://example.com/pkg.git\n",
        encoding="utf-8",
    )
    deps, manifests = parse_dependencies(tmp_path)
    assert manifests == 1
    by_name = {d.name: d for d in deps}
    assert by_name["django"].version == "3.2.0"
    assert by_name["requests"].version == "2.20"      # loose spec → representative version
    assert by_name["flask"].version == "2.0.1"        # extras stripped, pin kept
    assert "pkg" not in by_name                        # VCS URL skipped
    assert all(d.ecosystem == "PyPI" for d in deps)


def test_parse_package_json_and_lock(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "^4.17.19"}, "devDependencies": {"jest": "~29.0.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"": {"name": "root"}, "node_modules/lodash": {"version": "4.17.19"}}}',
        encoding="utf-8",
    )
    deps, manifests = parse_dependencies(tmp_path)
    assert manifests == 2
    names = {(d.name, d.version) for d in deps}
    assert ("lodash", "4.17.19") in names   # exact from lockfile
    assert ("jest", "29.0.0") in names      # cleaned from ~29.0.0
    assert all(d.ecosystem == "npm" for d in deps)


def test_parse_pyproject_pep621_and_poetry(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests>=2.0", "urllib3==1.26.5"]\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\nDjango = "^3.2"\n',
        encoding="utf-8",
    )
    deps, _ = parse_dependencies(tmp_path)
    by_name = {d.name: d.version for d in deps}
    assert by_name["urllib3"] == "1.26.5"
    assert by_name["django"] == "3.2"
    assert "python" not in by_name  # the poetry python constraint is not a dependency


def test_scan_flags_vulnerable_package_via_injected_source(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\nsafe-pkg==1.0.0\n", encoding="utf-8")

    def fake_source(deps: list[Dependency]) -> dict[str, list[Advisory]]:
        hits = {}
        for d in deps:
            if d.name == "django":
                hits[d.key()] = [
                    Advisory(id="GHSA-x", summary="SQLi in Django", severity="high", fixed="3.2.5")
                ]
        return hits

    report = scan_dependencies(tmp_path, source=fake_source)
    assert report.dependencies_scanned == 2
    assert report.advisory_source == "osv"
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.name == "django" and finding.severity == "high"
    assert finding.advisories[0].fixed == "3.2.5"
    assert report.by_severity == {"high": 1}


def test_scan_without_source_is_inventory_only(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n", encoding="utf-8")
    report = scan_dependencies(tmp_path, source=None)
    assert report.dependencies_scanned == 1
    assert report.findings == []
    assert report.advisory_source == "none"


def test_scan_empty_project(tmp_path):
    report = scan_dependencies(tmp_path, source=None)
    assert report.manifests_scanned == 0
    assert "No dependency manifests" in report.summary
