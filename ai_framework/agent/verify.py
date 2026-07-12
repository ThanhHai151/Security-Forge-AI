"""FindingVerifier — replay a finding's repro and confirm it before it's trusted.

A model asserting "SQLi here" is a *claim*; a red-team report needs *proof*. When the agent
records a finding it may attach a ``repro`` — a request to replay plus what a positive result
looks like (a marker string in the body and/or an expected status). This verifier re-issues that
request through the run's authenticated :class:`HttpSession` and only marks the finding
``verified`` when the expectation actually holds. No repro → unverified (surfaced as such).

Replays are scope-gated exactly like every other network action, and go through the same
session so authenticated findings reproduce correctly. The HTTP call is injectable so tests
confirm the *logic* (marker matched / status matched / mismatch) without a network.
"""

from __future__ import annotations

from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

from ai_framework.tools.base import ToolContext, require_authorized
from ai_framework.tools.session import session_of

_TIMEOUT = 10
_MAX_BODY = 16384


class FindingVerifier:
    """Replays ``repro`` and returns ``(verified, note)``."""

    def verify(self, repro: dict[str, Any], ctx: ToolContext) -> tuple[bool, str]:
        req_spec = repro.get("request") or {}
        url = str(req_spec.get("url", "")).strip()
        if not url:
            return False, "repro has no request.url"
        try:
            require_authorized(url, ctx)
        except PermissionError as exc:
            return False, f"repro target off-scope: {exc}"

        method = str(req_spec.get("method", "GET")).upper()
        headers = {str(k): str(v) for k, v in (req_spec.get("headers") or {}).items()}
        body = req_spec.get("body")
        data = body.encode("utf-8") if isinstance(body, str) and body else None
        req = Request(url, data=data, headers=headers, method=method)  # noqa: S310 - gated above
        try:
            with session_of(ctx).open(req, _TIMEOUT) as resp:
                status = resp.status
                text = resp.read(_MAX_BODY).decode("utf-8", "replace")
        except HTTPError as exc:  # a 4xx/5xx is a real result the expectation may target
            status = exc.code
            text = exc.read(_MAX_BODY).decode("utf-8", "replace") if exc.fp else ""
        except Exception as exc:  # noqa: BLE001 - transport failure => unverified, not a crash
            return False, f"replay failed: {type(exc).__name__}: {exc}"

        checks: list[str] = []
        ok = True
        if "expect" in repro:
            marker = str(repro["expect"])
            hit = marker in text
            ok = ok and hit
            checks.append(f"marker {marker!r} {'found' if hit else 'ABSENT'}")
        if "expect_status" in repro:
            want = int(repro["expect_status"])
            hit = status == want
            ok = ok and hit
            checks.append(f"status {status} {'==' if hit else '!='} {want}")
        if not checks:
            # A successful response only proves reachability, not a vulnerability. Requiring a
            # caller-defined differentiating signal prevents ordinary 2xx pages becoming
            # "verified" findings.
            return False, (
                f"replayed {method} {url} -> HTTP {status}; no explicit expect or "
                "expect_status supplied (unverified)"
            )
        verdict = "confirmed" if ok else "NOT reproduced"
        note = f"replayed {method} {url} -> HTTP {status}; " + "; ".join(checks) + f" ({verdict})"
        return ok, note
