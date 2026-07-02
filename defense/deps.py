"""SCA — parse a project's dependency manifests and flag known-vulnerable packages.

The signature scanner (``defense/signatures.py``) catches risky *code*; this catches risky
*dependencies* — the other half of assessing a project in the user's directory. It reads the
manifests/lockfiles a project ships (``requirements.txt``, ``pyproject.toml``, ``package.json``,
``package-lock.json``), extracts ``(ecosystem, name, version)``, and asks an **advisory source**
which of them have published CVEs, with the fixed version to upgrade to.

The advisory source is injectable (like ``external.py``'s runner) so tests never touch the
network. The default queries `OSV.dev <https://osv.dev>`_ and **degrades to "no data" offline**
rather than crashing — an offline review still returns the full dependency inventory.
"""

from __future__ import annotations

import json
import re
import tomllib
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path

from pydantic import BaseModel, Field

# Manifests we know how to read, newest-most-precise first (lockfiles pin exact versions).
_MANIFESTS = ("package-lock.json", "requirements.txt", "pyproject.toml", "package.json")
_SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".next",
     ".pytest_cache", ".mypy_cache", ".ruff_cache", "vendor", ".idea", ".vscode"}
)
_MAX_MANIFESTS = 200
_MAX_VULNS_PER_DEP = 20
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_OSV_VULN = "https://api.osv.dev/v1/vulns/"
# GitHub/OSV severity words → our band ("moderate" is GitHub's name for medium).
_SEVERITY_WORDS = {
    "critical": "critical", "high": "high", "moderate": "medium",
    "medium": "medium", "low": "low",
}


class Dependency(BaseModel):
    """One package a project depends on, as read from a manifest."""

    ecosystem: str  # "PyPI" | "npm" (OSV ecosystem names)
    name: str
    version: str = ""  # exact when pinned/locked; a representative version for a range; else ""
    source: str = ""   # manifest file it came from (relative to the scanned root)

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}:{self.version}"


class Advisory(BaseModel):
    """A published vulnerability affecting a specific dependency version."""

    id: str
    summary: str = ""
    severity: str = "unknown"  # critical|high|medium|low|unknown
    fixed: str = ""            # the version that resolves it, when known
    reference: str = ""


class DependencyFinding(BaseModel):
    """A dependency with at least one advisory against its version."""

    ecosystem: str
    name: str
    version: str
    source: str
    severity: str = "unknown"  # worst advisory severity — the sort key
    advisories: list[Advisory] = Field(default_factory=list)


class DependencyReport(BaseModel):
    target: str
    advisory_source: str = "osv"   # "osv" (queried) | "none" (offline / no source)
    manifests_scanned: int = 0
    dependencies_scanned: int = 0
    findings: list[DependencyFinding] = Field(default_factory=list)
    by_severity: dict[str, int] = Field(default_factory=dict)
    summary: str = ""


# An advisory source maps each dependency (by ``key()``) to the advisories against it.
AdvisorySource = Callable[[list[Dependency]], dict[str, list[Advisory]]]


# --- Manifest parsing (pure, no network) ------------------------------------


def _clean_version(spec: str) -> str:
    """Best-effort exact version from a spec like ``^1.2.3`` / ``>=2.0`` / ``==1.4`` → digits."""
    m = re.search(r"(\d+(?:\.\d+)*)", spec)
    return m.group(1) if m else ""


def _parse_requirements(text: str, rel: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line:
            continue  # skip blanks, flags (-r/-e/--hash), and direct URLs
        pinned = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;]+)", line)
        if pinned:
            deps.append(Dependency(
                ecosystem="PyPI", name=pinned.group(1).lower(), version=pinned.group(2), source=rel
            ))
            continue
        loose = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$", line)
        if loose:
            deps.append(Dependency(
                ecosystem="PyPI", name=loose.group(1).lower(),
                version=_clean_version(loose.group(2)), source=rel,
            ))
    return deps


def _parse_pyproject(text: str, rel: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    deps: list[Dependency] = []
    project = data.get("project", {})
    specs: list[str] = list(project.get("dependencies", []) or [])
    for group in (project.get("optional-dependencies", {}) or {}).values():
        specs.extend(group or [])
    for spec in specs:
        text_spec = str(spec).strip()
        m = re.match(r"^([A-Za-z0-9._-]+)", text_spec)
        if m:
            # Clean the version from the constraint *after* the name — a name like "urllib3"
            # carries a digit that would otherwise be misread as the version.
            deps.append(Dependency(
                ecosystem="PyPI", name=m.group(1).lower(),
                version=_clean_version(text_spec[m.end():]), source=rel,
            ))
    # Poetry-style table: {name: version-spec}
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else str(spec.get("version", ""))
        deps.append(Dependency(
            ecosystem="PyPI", name=name.lower(), version=_clean_version(version), source=rel
        ))
    return deps


def _parse_package_json(text: str, rel: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            deps.append(Dependency(
                ecosystem="npm", name=str(name), version=_clean_version(str(spec)), source=rel
            ))
    return deps


def _parse_package_lock(text: str, rel: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[Dependency] = []
    # npm lockfile v2/v3: exact versions under "packages" keyed by node_modules path.
    for pkg_path, meta in (data.get("packages") or {}).items():
        if not pkg_path or not isinstance(meta, dict):
            continue  # "" is the project root itself
        name = pkg_path.split("node_modules/")[-1]
        version = str(meta.get("version", ""))
        if name and version:
            deps.append(Dependency(ecosystem="npm", name=name, version=version, source=rel))
    # npm lockfile v1: "dependencies" tree.
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and meta.get("version"):
            deps.append(Dependency(
                ecosystem="npm", name=str(name), version=str(meta["version"]), source=rel
            ))
    return deps


_PARSERS: dict[str, Callable[[str, str], list[Dependency]]] = {
    "requirements.txt": _parse_requirements,
    "pyproject.toml": _parse_pyproject,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
}


def _iter_manifests(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name not in _MANIFESTS:
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def parse_dependencies(target: str | Path) -> tuple[list[Dependency], int]:
    """Return ``(dependencies, manifests_scanned)`` for a file or directory. Pure, no network."""
    root = Path(target).resolve()
    manifests = [root] if root.is_file() and root.name in _PARSERS else list(_iter_manifests(root))
    seen: set[str] = set()
    deps: list[Dependency] = []
    scanned = 0
    for path in manifests[:_MAX_MANIFESTS]:
        parser = _PARSERS.get(path.name)
        if parser is None:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        for dep in parser(text, rel):
            if dep.key() not in seen:
                seen.add(dep.key())
                deps.append(dep)
    return deps, scanned


# --- Advisory lookup (OSV, best-effort + injectable) ------------------------


def _get_json(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed OSV endpoint
        return json.loads(resp.read().decode("utf-8"))


def _post_json(url: str, payload: dict, timeout: float = 20.0) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed OSV endpoint
        return json.loads(resp.read().decode("utf-8"))


def _osv_severity(detail: dict) -> str:
    word = str(detail.get("database_specific", {}).get("severity", "")).lower()
    return _SEVERITY_WORDS.get(word, "unknown")


def _osv_fixed(detail: dict, ecosystem: str) -> str:
    for affected in detail.get("affected", []):
        if affected.get("package", {}).get("ecosystem") not in (ecosystem, None):
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if event.get("fixed"):
                    return str(event["fixed"])
    return ""


def _osv_detail(vuln_id: str, ecosystem: str) -> Advisory:
    ref = f"https://osv.dev/vulnerability/{vuln_id}"
    try:
        detail = _get_json(_OSV_VULN + vuln_id)
    except Exception:  # noqa: BLE001 - offline / API hiccup: still report the id
        return Advisory(id=vuln_id, reference=ref)
    return Advisory(
        id=vuln_id,
        summary=str(detail.get("summary", "") or detail.get("details", ""))[:300],
        severity=_osv_severity(detail),
        fixed=_osv_fixed(detail, ecosystem),
        reference=ref,
    )


def osv_source(deps: list[Dependency]) -> dict[str, list[Advisory]]:
    """Default advisory source: query OSV.dev. Returns ``{}`` on any network/parse failure."""
    scannable = [d for d in deps if d.version]
    if not scannable:
        return {}
    queries = [
        {"version": d.version, "package": {"name": d.name, "ecosystem": d.ecosystem}}
        for d in scannable
    ]
    try:
        resp = _post_json(_OSV_BATCH, {"queries": queries})
    except Exception:  # noqa: BLE001 - offline is fine; the inventory still ships
        return {}
    out: dict[str, list[Advisory]] = {}
    detail_cache: dict[str, Advisory] = {}
    for dep, result in zip(scannable, resp.get("results", []), strict=False):
        advisories: list[Advisory] = []
        for vuln in (result.get("vulns") or [])[:_MAX_VULNS_PER_DEP]:
            vid = str(vuln.get("id", ""))
            if not vid:
                continue
            if vid not in detail_cache:
                detail_cache[vid] = _osv_detail(vid, dep.ecosystem)
            advisories.append(detail_cache[vid])
        if advisories:
            out[dep.key()] = advisories
    return out


# --- Top-level scan ---------------------------------------------------------


def _worst(advisories: list[Advisory]) -> str:
    return min((a.severity for a in advisories), key=lambda s: _SEVERITY_RANK.get(s, 4),
               default="unknown")


def scan_dependencies(
    target: str | Path, source: AdvisorySource | None = osv_source
) -> DependencyReport:
    """Inventory a project's dependencies and report those with known advisories.

    ``source`` is injectable: pass a fake in tests, ``None`` to skip lookups (inventory only),
    or leave the default to query OSV (degrading to inventory-only when offline).
    """
    root = Path(target).resolve()
    deps, manifests = parse_dependencies(root)
    advisories_by_dep = source(deps) if source is not None else {}
    findings: list[DependencyFinding] = []
    for dep in deps:
        advisories = advisories_by_dep.get(dep.key(), [])
        if not advisories:
            continue
        findings.append(DependencyFinding(
            ecosystem=dep.ecosystem, name=dep.name, version=dep.version, source=dep.source,
            severity=_worst(advisories), advisories=advisories,
        ))
    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 4), f.name))
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return DependencyReport(
        target=str(root),
        advisory_source="none" if (source is None or not advisories_by_dep) else "osv",
        manifests_scanned=manifests,
        dependencies_scanned=len(deps),
        findings=findings,
        by_severity=by_severity,
        summary=_summarize(len(deps), manifests, findings),
    )


def _summarize(dep_count: int, manifests: int, findings: list[DependencyFinding]) -> str:
    if not manifests:
        return "No dependency manifests found."
    if not findings:
        return f"Scanned {dep_count} dependencies across {manifests} manifest(s); none vulnerable."
    vulns = sum(len(f.advisories) for f in findings)
    return (
        f"Scanned {dep_count} dependencies across {manifests} manifest(s); "
        f"{len(findings)} vulnerable package(s), {vulns} advisory(ies)."
    )
