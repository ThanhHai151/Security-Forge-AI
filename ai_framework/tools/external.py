"""``run_recon`` — drive real external pentest CLIs, scope-gated and sandbox-friendly.

The stdlib HTTP tools can only *read*; a real engagement reaches for httpx, nuclei, ffuf,
nmap, subfinder, and friends. This tool exposes a **curated allow-list** of those binaries
behind one schema, so the model picks a tool + target and SecForge:

* **scope-gates every host** in the final argv through :func:`require_authorized_host` — the
  same gate the HTTP tools use, so an external CLI can never be pointed off-scope;
* builds ``argv`` itself (no shell, ``shell=False``) from a per-tool template, so there is no
  shell-injection surface;
* runs through an **injectable runner** (``ctx.runner``) so tests never touch the network or
  need the binary installed, and a missing binary degrades to a clear message, not a crash;
* marks intrusive scanners (nuclei, ffuf, nikto, sqlmap, …) ``mutating`` so campaign mode holds
  them for operator approval, while passive recon (httpx, subfinder, whatweb, …) runs freely.

Nothing here is installed by SecForge; if a binary is absent the tool says so. This is an
authorized-engagement capability — the scope gate is the guardrail.
"""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404 - argv is built here (no shell); hosts are scope-gated
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ai_framework.tools.base import ToolContext, require_authorized_host

# (argv, timeout) -> (returncode, stdout, stderr). Injectable so tests need no binaries.
Runner = Callable[[list[str], float], tuple[int, str, str]]

_TIMEOUT = 120.0
_MAX_OUTPUT = 8000  # chars of combined stdout/stderr kept in the log


@dataclass(frozen=True)
class Preset:
    """One allow-listed CLI: how to build its argv and how intrusive it is."""

    binary: str
    build: Callable[[str, dict[str, Any]], list[str]]
    mutating: bool = False  # True => active/intrusive => held for approval in campaigns
    needs: tuple[str, ...] = field(default_factory=tuple)  # extra required arg names
    summary: str = ""


def _host_of(target: str) -> str:
    """Host for a URL, or the bare token for a domain/host target."""
    if "://" in target:
        return urlparse(target).hostname or ""
    return target.split("/")[0]


def _extra(opts: dict[str, Any]) -> list[str]:
    raw = opts.get("extra_args") or []
    if not isinstance(raw, list):
        raise ValueError("extra_args must be a list of strings")
    out = [str(a) for a in raw]
    if any(len(a) > 512 for a in out) or len(out) > 40:
        raise ValueError("extra_args too large")
    return out


def _wordlist(opts: dict[str, Any]) -> str:
    wl = str(opts.get("wordlist", "")).strip()
    if not wl:
        raise ValueError("this tool requires a 'wordlist' path")
    return wl


# Curated allow-list. Each builder receives (target, opts) and returns full argv.
PRESETS: dict[str, Preset] = {
    "httpx": Preset("httpx", lambda t, o: ["httpx", "-silent", "-u", t, *_extra(o)],
                    summary="probe/fingerprint a URL (status, tech, title)"),
    "whatweb": Preset("whatweb", lambda t, o: ["whatweb", "--color=never", t, *_extra(o)],
                      summary="identify web technologies"),
    "wafw00f": Preset("wafw00f", lambda t, o: ["wafw00f", t, *_extra(o)],
                      summary="detect a WAF in front of the site"),
    "nmap": Preset("nmap", lambda t, o: ["nmap", "-sV", "-T3", _host_of(t), *_extra(o)],
                   summary="service/version scan of a host"),
    "naabu": Preset("naabu", lambda t, o: ["naabu", "-silent", "-host", _host_of(t), *_extra(o)],
                    summary="fast port scan of a host"),
    "subfinder": Preset(
        "subfinder", lambda t, o: ["subfinder", "-silent", "-d", _host_of(t), *_extra(o)],
        summary="passive subdomain enumeration of an authorized apex domain"),
    "dnsx": Preset("dnsx", lambda t, o: ["dnsx", "-silent", "-d", _host_of(t), *_extra(o)],
                   summary="DNS resolution/records for a domain"),
    "katana": Preset("katana", lambda t, o: ["katana", "-silent", "-u", t, *_extra(o)],
                     summary="crawl a site for endpoints (read-only)"),
    "nuclei": Preset(
        "nuclei", lambda t, o: ["nuclei", "-silent", "-u", t, *_extra(o)], mutating=True,
        summary="active template-based vulnerability scan"),
    "nikto": Preset("nikto", lambda t, o: ["nikto", "-h", t, *_extra(o)], mutating=True,
                    summary="active web-server misconfiguration scan"),
    "ffuf": Preset(
        "ffuf", lambda t, o: ["ffuf", "-u", f"{t.rstrip('/')}/FUZZ", "-w", _wordlist(o),
                              "-mc", "200,204,301,302,307,401,403", *_extra(o)],
        mutating=True, needs=("wordlist",), summary="content/endpoint fuzzing (needs wordlist)"),
    "gobuster": Preset(
        "gobuster", lambda t, o: ["gobuster", "dir", "-q", "-u", t, "-w", _wordlist(o), *_extra(o)],
        mutating=True, needs=("wordlist",), summary="directory brute force (needs wordlist)"),
    "sqlmap": Preset(
        "sqlmap", lambda t, o: ["sqlmap", "-u", t, "--batch", *_extra(o)], mutating=True,
        summary="active SQL-injection testing"),
}


def _default_runner(argv: list[str], timeout: float) -> tuple[int, str, str]:
    proc = subprocess.run(  # noqa: S603 - argv built from a preset, shell=False, hosts gated
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr


def _gate_hosts(argv: list[str], ctx: ToolContext) -> None:
    """Scope-gate every host-like token in the final argv (defense in depth)."""
    for tok in argv[1:]:
        if "://" in tok:
            require_authorized_host(urlparse(tok).hostname or "", ctx)
        elif "/" not in tok and "." in tok and not tok.startswith("-"):
            # Looks like a bare host/domain (not a flag, not a path). Gate it.
            require_authorized_host(tok, ctx)


class ExternalReconTool:
    name = "run_recon"
    description = (
        "Run an allow-listed external pentest CLI against an authorized target and return its "
        "output. tool ∈ {" + ", ".join(sorted(PRESETS)) + "}. Every host is scope-gated; "
        "intrusive scanners (nuclei, ffuf, gobuster, nikto, sqlmap) are held for approval in "
        "campaign mode. If the binary isn't installed, it says so."
    )
    touches_network = True
    mutating = False  # per-call: overridden by the chosen preset (see is_mutating_call)

    def is_mutating_call(self, args: dict[str, Any]) -> bool:
        """Per-call intrusiveness — an intrusive preset is held for approval in campaigns."""
        return is_mutating_call(args)

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "enum": sorted(PRESETS)},
                "target": {"type": "string", "description": "URL or host/domain (scope-gated)"},
                "wordlist": {"type": "string", "description": "Path to a wordlist (ffuf/gobuster)"},
                "extra_args": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Extra CLI flags (no shell; off-scope hosts are rejected)",
                },
            },
            "required": ["tool", "target"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        tool = str(args.get("tool", ""))
        target = str(args.get("target", "")).strip()
        preset = PRESETS.get(tool)
        if preset is None:
            raise ValueError(f"unknown tool {tool!r}; choose one of {', '.join(sorted(PRESETS))}")
        if not target:
            raise ValueError("target is required")
        require_authorized_host(_host_of(target), ctx)  # gate the primary target first
        argv = preset.build(target, args)
        _gate_hosts(argv, ctx)  # then gate any host smuggled via extra_args

        runner: Runner = ctx.runner or _default_runner
        if ctx.runner is None and shutil.which(preset.binary) is None:
            return (
                f"[{tool}] not installed — install it to run this scan, or use the built-in "
                f"HTTP tools. (argv would be: {' '.join(argv)})"
            )
        try:
            rc, out, err = runner(argv, _TIMEOUT)
        except FileNotFoundError:
            return f"[{tool}] not installed (binary {preset.binary!r} not found on PATH)."
        except subprocess.TimeoutExpired:
            return f"[{tool}] timed out after {_TIMEOUT:.0f}s: {' '.join(argv)}"
        body = (out or "") + (f"\n[stderr]\n{err}" if err else "")
        body = body.strip() or "(no output)"
        if len(body) > _MAX_OUTPUT:
            body = body[:_MAX_OUTPUT] + f"\n… [truncated, exit={rc}]"
        return f"$ {' '.join(argv)}\n[exit {rc}]\n{body}"


def is_mutating_call(args: dict[str, Any]) -> bool:
    """Whether a specific ``run_recon`` call is intrusive (used by the guardrail/campaign hold)."""
    preset = PRESETS.get(str(args.get("tool", "")))
    return bool(preset and preset.mutating)
