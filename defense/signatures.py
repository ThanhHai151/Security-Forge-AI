"""Code-pattern signatures, one set of high-signal regexes per vulnerability class.

Each :class:`Signature` ties a pattern to a **catalog slug** so a match can pull that class's
"Defenses" guidance straight from the knowledge base. These are deliberately conservative
(favouring precision) — the static scan is the always-available offline path; the agent loop
(``ai_framework`` via ``backend.RunService``) is the deeper, dynamic complement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signature:
    slug: str  # catalog class this maps to (e.g. "sql_injection")
    message: str  # what's risky about the match
    pattern: re.Pattern[str]
    severity: str = "medium"  # critical | high | medium | low
    exts: frozenset[str] = field(default_factory=frozenset)  # empty = any text file

    def applies_to(self, ext: str) -> bool:
        return not self.exts or ext.lower() in self.exts


_PY = frozenset({".py"})
_JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_WEB = frozenset({".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".svelte"})


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def default_signatures() -> list[Signature]:
    """The bundled signature set. Add a Signature to cover a new class (the extension point)."""
    return [
        # ── Injection ──
        Signature(
            "sql_injection",
            "SQL built by string formatting/concatenation — use parameterized queries",
            _re(r"""(execute|executemany|cursor\.execute|query)\s*\(\s*[fr]?["'].*?(%s?|\+|\{|\.format)"""),
            "critical",
            _PY,
        ),
        Signature(
            "sql_injection",
            "SQL string interpolation with user data — use bound parameters",
            _re(r"""(SELECT|INSERT|UPDATE|DELETE)\b.*?["']\s*\+\s*\w|\b(SELECT|UPDATE|DELETE)\b.*?\$\{"""),
            "high",
        ),
        Signature(
            "os_command_injection",
            "Shell invocation with interpolated input — avoid shell=True / pass an argv list",
            _re(r"""(os\.system|os\.popen|subprocess\.(call|run|Popen)[^)]*shell\s*=\s*True)"""),
            "critical",
            _PY,
        ),
        Signature(
            "os_command_injection",
            "child_process.exec with a dynamic command — use execFile/spawn with an argv array",
            _re(r"""child_process\.(exec|execSync)\s*\(|\brequire\(['"]child_process['"]\)\.exec"""),
            "high",
            _JS,
        ),
        Signature(
            "insecure_deserialization",
            "Unsafe deserialization of untrusted data",
            _re(r"""\b(pickle\.loads?|yaml\.load\s*\((?!.*Safe)|cPickle\.loads?|marshal\.loads?)\b"""),
            "critical",
            _PY,
        ),
        Signature(
            "insecure_deserialization",
            "unserialize()/node-serialize on untrusted input",
            _re(r"""\bunserialize\s*\(|node-serialize"""),
            "high",
        ),
        Signature(
            "ssti",
            "Template rendered from a string — server-side template injection risk",
            _re(r"""render_template_string\s*\(|Template\s*\(.*\)\.render\("""),
            "high",
            _PY,
        ),
        # ── Dangerous evaluation ──
        Signature(
            "os_command_injection",
            "Dynamic code evaluation of (possibly) untrusted input",
            _re(r"""\beval\s*\(|\bexec\s*\(|new\s+Function\s*\("""),
            "high",
        ),
        # ── Client-side ──
        Signature(
            "xss",
            "Raw HTML sink — output is not escaped (XSS)",
            _re(r"""dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(|insertAdjacentHTML"""),
            "high",
            _WEB,
        ),
        Signature(
            "xss",
            "Autoescaping disabled / value marked safe in a template",
            _re(r"""\|\s*safe\b|autoescape\s*=\s*False|Markup\s*\("""),
            "high",
        ),
        # ── Server-side ──
        Signature(
            "ssrf",
            "Outbound request to a user-controlled URL — validate against an allow-list (SSRF)",
            _re(r"""(requests\.(get|post|put|head)|urlopen|httpx\.(get|post)|fetch)\s*\(\s*(request|req|params|input|url_from|user)"""),
            "high",
        ),
        Signature(
            "path_traversal",
            "File path built from request input — canonicalize and confine to a base dir",
            _re(r"""(open|send_file|sendFile|readFile|os\.path\.join)\s*\([^)]*(request|req\.|params|input|user)"""),
            "high",
        ),
        # ── Auth / identity ──
        Signature(
            "jwt",
            "JWT signature verification weakened (alg 'none' or verify disabled)",
            _re(r"""algorithms\s*=\s*\[?\s*['"]none['"]|verify(_signature)?\s*[=:]\s*(False|false)"""),
            "critical",
        ),
        Signature(
            "broken_authentication",
            "Hardcoded credential/secret — load from the environment or a secret manager",
            _re(r"""(password|passwd|secret|api[_-]?key|token|aws_secret)\s*[:=]\s*["'][^"'\s]{6,}["']"""),
            "high",
        ),
        # ── CORS ──
        Signature(
            "cors",
            "Wildcard CORS origin — reflects any site; scope it and avoid '*' with credentials",
            _re(r"""Access-Control-Allow-Origin["']?\s*[:,]\s*["']?\*|origins\s*=\s*["']\*["']|cors\(\s*\)"""),
            "medium",
        ),
        # ── TLS / transport ──
        Signature(
            "information_disclosure",
            "TLS verification disabled — restores MITM exposure",
            _re(r"""verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"""),
            "high",
        ),
    ]
