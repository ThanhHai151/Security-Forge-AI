"""Framework mapping — tie every catalogued web-vuln class to the industry taxonomies.

A real red-team report speaks CWE / OWASP / MITRE ATT&CK, and testers navigate by OWASP WSTG.
This module maps each ``vuln_search/catalog/<slug>`` to those references so a finding can carry
"CWE-89 · OWASP A03:2021 · ATT&CK T1190 · WSTG-INPV-05" instead of a bare title.

Values are conservative and sourced from the public taxonomies: CWE is always present (the most
precise), OWASP is the Top-10 (or API/LLM Top-10) category, ATT&CK is the closest enterprise
technique (often T1190 *Exploit Public-Facing Application* for a server-side web bug), and WSTG
is the OWASP Testing Guide id where there is a clean one — left empty rather than guessed.
"""

from __future__ import annotations

from typing import Any


def _m(cwe: list[str], owasp: str, attack: list[str] | None = None,
       wstg: list[str] | None = None) -> dict[str, Any]:
    return {"cwe": cwe, "owasp": owasp, "attack": attack or [], "wstg": wstg or []}


# Keyed by catalog slug (the directory name under vuln_search/catalog/).
FRAMEWORK_MAP: dict[str, dict[str, Any]] = {
    "api_security": _m(["CWE-284"], "OWASP API Security Top 10", ["T1190"]),
    "broken_access_control": _m(["CWE-284", "CWE-639"], "A01:2021-Broken Access Control",
                                ["T1190"], ["WSTG-ATHZ-02"]),
    "broken_authentication": _m(["CWE-287"], "A07:2021-Identification and Authentication Failures",
                                ["T1110", "T1078"], ["WSTG-ATHN-03"]),
    "clickjacking": _m(["CWE-1021"], "A05:2021-Security Misconfiguration", [], ["WSTG-CLNT-09"]),
    "cors": _m(["CWE-942"], "A05:2021-Security Misconfiguration"),
    "csrf": _m(["CWE-352"], "A01:2021-Broken Access Control", [], ["WSTG-SESS-05"]),
    "dom_based": _m(["CWE-79"], "A03:2021-Injection", ["T1059.007"], ["WSTG-CLNT-01"]),
    "file_upload": _m(["CWE-434"], "A04:2021-Insecure Design", ["T1505.003"], ["WSTG-BUSL-09"]),
    "graphql": _m(["CWE-200"], "OWASP API Security Top 10", [], ["WSTG-APIT-01"]),
    "http_host_header": _m(["CWE-644"], "A03:2021-Injection", [], ["WSTG-INPV-17"]),
    "http_request_smuggling": _m(["CWE-444"], "A03:2021-Injection", ["T1190"]),
    "information_disclosure": _m(["CWE-200"], "A01:2021-Broken Access Control", ["T1592"]),
    "insecure_deserialization": _m(["CWE-502"], "A08:2021-Software and Data Integrity Failures",
                                   ["T1059"]),
    "jwt": _m(["CWE-347"], "A02:2021-Cryptographic Failures", ["T1550.001"]),
    "llm_attacks": _m(["CWE-1427"], "OWASP Top 10 for LLM Applications (LLM01 Prompt Injection)"),
    "nosql_injection": _m(["CWE-943"], "A03:2021-Injection", ["T1190"], ["WSTG-INPV-05"]),
    "oauth": _m(["CWE-346"], "A07:2021-Identification and Authentication Failures", ["T1550"]),
    "os_command_injection": _m(["CWE-78"], "A03:2021-Injection", ["T1059"], ["WSTG-INPV-12"]),
    "path_traversal": _m(["CWE-22"], "A01:2021-Broken Access Control", ["T1083"], ["WSTG-ATHZ-01"]),
    "prototype_pollution": _m(["CWE-1321"], "A03:2021-Injection"),
    "race_condition": _m(["CWE-362"], "A04:2021-Insecure Design"),
    "sql_injection": _m(["CWE-89"], "A03:2021-Injection", ["T1190"], ["WSTG-INPV-05"]),
    "ssrf": _m(["CWE-918"], "A10:2021-Server-Side Request Forgery", ["T1190"], ["WSTG-INPV-19"]),
    "ssti": _m(["CWE-1336", "CWE-94"], "A03:2021-Injection", ["T1059"], ["WSTG-INPV-18"]),
    "web_cache_deception": _m(["CWE-525"], "A05:2021-Security Misconfiguration"),
    "web_cache_poisoning": _m(["CWE-349", "CWE-444"], "A03:2021-Injection"),
    "websockets": _m(["CWE-1385"], "A05:2021-Security Misconfiguration", [], ["WSTG-CLNT-10"]),
    "xss": _m(["CWE-79"], "A03:2021-Injection", ["T1059.007"], ["WSTG-INPV-01"]),
    "xxe": _m(["CWE-611"], "A05:2021-Security Misconfiguration", ["T1190"], ["WSTG-INPV-07"]),
}


def mapping_for(slug: str) -> dict[str, Any]:
    """Framework references for a catalog slug (empty-but-shaped dict if unmapped)."""
    return FRAMEWORK_MAP.get(slug, {"cwe": [], "owasp": "", "attack": [], "wstg": []})


def label(slug: str) -> str:
    """One-line ``CWE-89 · A03:2021-Injection · ATT&CK T1190 · WSTG-INPV-05`` summary."""
    m = mapping_for(slug)
    parts: list[str] = list(m["cwe"])
    if m["owasp"]:
        parts.append(m["owasp"])
    parts += [f"ATT&CK {a}" for a in m["attack"]]
    parts += m["wstg"]
    return " · ".join(parts)
