"""Static, per-technique grep signals for ranking source files in a whitebox investigation.

Cheap, offline heuristics only — a regex pass over local source, no execution and no network.
These are hints for *where to look first* so an external coding agent (Claude Code) doesn't
burn tool calls reading low-probability files; they are not proof of a vulnerability, and this
module never claims one. Extend ``WHITEBOX_SIGNALS`` as real engagements reveal gaps.
"""

from __future__ import annotations

import re
from pathlib import Path

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "vendor", "target",
}
_SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".rb", ".php", ".go", ".cs", ".cpp",
    ".c", ".kt", ".scala", ".sql",
}
_MAX_FILE_BYTES = 1_000_000
_MAX_FILES_SCANNED = 5_000

WHITEBOX_SIGNALS: dict[str, tuple[str, ...]] = {
    "sql_injection": (
        r"cursor\.execute\([^)]*%", r"cursor\.execute\([^)]*\+", r"\.raw\(",
        r"f[\"'][^\"']*SELECT", r"\+\s*[\"']\s*(SELECT|WHERE|FROM)", r"execute\(f[\"']",
        r"String\.format\([^)]*(SELECT|WHERE)", r"createStatement\(", r"\.query\([^)]*\+",
    ),
    "nosql_injection": (
        r"\$where", r"\.find\(\{[^}]*req\.", r"JSON\.parse\(req\.",
    ),
    "os_command_injection": (
        r"os\.system\(", r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True",
        r"\bexec\(", r"Runtime\.getRuntime\(\)\.exec\(", r"child_process",
    ),
    "ssti": (
        r"render_template_string\(", r"Template\([^)]*request", r"engine\.render\(",
    ),
    "xxe": (
        r"XMLParser\(", r"DocumentBuilderFactory", r"resolve_entities\s*=\s*True",
    ),
    "path_traversal": (
        r"open\([^)]*request\.", r"send_file\(", r"\.\./",
    ),
    "xss": (
        r"innerHTML\s*=", r"dangerouslySetInnerHTML", r"\|\s*safe\b", r"mark_safe\(",
    ),
    "broken_authentication": (
        r"\bmd5\(", r"\bsha1\(", r"==\s*password\b", r"compare_digest",
    ),
    "broken_access_control": (
        r"@login_required", r"if\s+.*role\s*==", r"request\.user\.id",
    ),
    "ssrf": (
        r"requests\.get\([^)]*request\.", r"urlopen\([^)]*request\.", r"fetch\([^)]*req\.",
    ),
    "insecure_deserialization": (
        r"pickle\.loads\(", r"yaml\.load\((?!.*Loader)", r"ObjectInputStream",
    ),
    "file_upload": (
        r"secure_filename", r"\.save\([^)]*filename", r"multer\(",
    ),
}


def signals_for(node_id: str) -> tuple[str, ...]:
    return WHITEBOX_SIGNALS.get(node_id, ())


def _iter_source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in _SOURCE_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def rank_files(project_path: str | Path, node_id: str, max_results: int = 20) -> list[dict]:
    """Rank local source files by how many technique signals they match.

    Returns ``[{"path": relative_str, "hits": int}]``, highest-hit first, empty if the
    project path doesn't exist or the technique has no signal table.
    """
    root = Path(project_path)
    patterns = signals_for(node_id)
    if not root.is_dir() or not patterns:
        return []
    compiled = [re.compile(p) for p in patterns]
    scored: list[tuple[int, Path]] = []
    for i, path in enumerate(_iter_source_files(root)):
        if i >= _MAX_FILES_SCANNED:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        hits = sum(1 for pat in compiled if pat.search(text))
        if hits:
            scored.append((hits, path))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [
        {"path": str(path.relative_to(root)), "hits": hits}
        for hits, path in scored[:max_results]
    ]
