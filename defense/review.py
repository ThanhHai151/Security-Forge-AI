"""Review a project directory for the catalogued vulnerability classes.

``review_path`` walks a codebase **read-only**, applies the signature set line by line, and
returns a prioritized :class:`DefenseReport`. Every finding carries the secure-implementation
guidance for its class — pulled from that class's "Defenses" section in the knowledge base —
plus a re-check hint, so the report maps weakness → fix the way ``defense/README.md`` asks.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from defense.signatures import Signature, default_signatures
from knowledge_base.index import KnowledgeBase, repo_root, section

# Source extensions worth scanning; everything else (binaries, media, locks) is skipped.
TEXT_EXTS = frozenset(
    {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".svelte",
     ".php", ".rb", ".go", ".java", ".cs", ".sql", ".yaml", ".yml", ".env", ".ini", ".conf",
     ".sh", ".bash"}
)
SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".next",
     ".pytest_cache", ".mypy_cache", ".ruff_cache", "vendor", ".idea", ".vscode"}
)
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_MAX_FILE_BYTES = 1_000_000  # skip very large files (generated bundles, data dumps)


class Finding(BaseModel):
    slug: str  # catalog class
    title: str  # human title of the class
    severity: str
    file: str  # path relative to the reviewed root
    line: int
    snippet: str
    message: str  # why this line is risky
    guidance: str = ""  # secure-implementation guidance (from the KB "Defenses" section)


class DefenseReport(BaseModel):
    target: str
    files_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_class: dict[str, int] = Field(default_factory=dict)
    summary: str = ""


def _guidance_for(kb: KnowledgeBase, slug: str) -> tuple[str, str]:
    """(class title, 'Defenses' guidance) for a catalog slug; empty when not catalogued."""
    entry = kb.get(slug, "en")
    if not entry:
        return slug.replace("_", " ").title(), ""
    return entry.title, section(kb.body(slug, "en"), "Defenses")


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.suffix.lower() not in TEXT_EXTS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def review_path(
    target: str | Path,
    signatures: list[Signature] | None = None,
    kb: KnowledgeBase | None = None,
) -> DefenseReport:
    """Scan ``target`` (a file or directory) and return a prioritized report."""
    root = Path(target).resolve()
    sigs = signatures if signatures is not None else default_signatures()
    kb = kb or KnowledgeBase(repo_root() / "vuln_search" / "catalog").index()
    guidance_cache: dict[str, tuple[str, str]] = {}

    files = [root] if root.is_file() else list(_iter_files(root))
    findings: list[Finding] = []
    scanned = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        ext = path.suffix.lower()
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for sig in sigs:
                if not sig.applies_to(ext) or not sig.pattern.search(line):
                    continue
                if sig.slug not in guidance_cache:
                    guidance_cache[sig.slug] = _guidance_for(kb, sig.slug)
                title, guidance = guidance_cache[sig.slug]
                findings.append(
                    Finding(
                        slug=sig.slug,
                        title=title,
                        severity=sig.severity,
                        file=rel,
                        line=lineno,
                        snippet=line.strip()[:200],
                        message=sig.message,
                        guidance=guidance,
                    )
                )

    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), f.file, f.line))
    by_severity: dict[str, int] = {}
    by_class: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_class[f.slug] = by_class.get(f.slug, 0) + 1
    summary = _summarize(scanned, findings, by_severity)
    return DefenseReport(
        target=str(root),
        files_scanned=scanned,
        findings=findings,
        by_severity=by_severity,
        by_class=by_class,
        summary=summary,
    )


def _summarize(scanned: int, findings: list[Finding], by_severity: dict[str, int]) -> str:
    if not findings:
        return f"Scanned {scanned} file(s); no catalogued weaknesses matched the signature set."
    order = ("critical", "high", "medium", "low")
    parts = [f"{by_severity[s]} {s}" for s in order if by_severity.get(s)]
    return f"Scanned {scanned} file(s); {len(findings)} finding(s): " + ", ".join(parts) + "."


def recheck(
    finding: Finding, target: str | Path, signatures: list[Signature] | None = None
) -> bool:
    """Confirm a finding still reproduces — the README's 'Re-check' step. True = still present."""
    root = Path(target).resolve()
    path = root if root.is_file() else root / finding.file
    if not path.is_file():
        return False
    sigs = signatures if signatures is not None else default_signatures()
    relevant = [s for s in sigs if s.slug == finding.slug and s.message == finding.message]
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    if 1 <= finding.line <= len(lines):
        line = lines[finding.line - 1]
        return any(s.pattern.search(line) for s in relevant)
    return False
