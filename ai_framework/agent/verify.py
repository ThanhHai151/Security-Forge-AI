"""FindingVerifier — replay a finding's repro and confirm it before it's trusted.

A model asserting "SQLi here" is a *claim*; a red-team report needs *proof*. When the agent
records a finding it may attach a ``repro`` — a request to replay plus what a positive result
looks like (a marker string in the body and/or an expected status). This verifier re-issues that
request through the run's authenticated :class:`HttpSession` and only marks the finding
``verified`` when the expectation actually holds. No repro → unverified (surfaced as such).

Safety (the replay is a real request against the target, so it is gated like any other action):

* **Read-only only.** The method comes from the model-supplied repro, so it is constrained to a
  safe allow-list (GET/HEAD/OPTIONS). A repro asking to replay POST/PUT/PATCH/DELETE is refused
  and returned unverified — a state-changing proof must go through the operator approval flow,
  never through automatic verification. (This closes the ARCHITECTURE.md P0 where a
  ``note_finding`` repro could fire a real DELETE outside every control.)
* **RoE-gated.** When an RoE is present the replay is evaluated by the same deterministic action
  policy as every tool call (scope, testing window, exclusions, disposition); a prohibited or
  unapproved replay is refused.
* **Rate-limited and audited.** The replay is paced/concurrency-bound by the run's
  :class:`EngagementLimiter` and recorded on the evidence ledger, so a verification request is
  reconstructable and never bypasses the run's budget.

The HTTP call is injectable so tests confirm the *logic* (marker/status matched or not) without
a network.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

from ai_framework.tools.base import ToolContext, require_authorized
from ai_framework.tools.session import session_of

_TIMEOUT = 10
_MAX_BODY = 16384
# A finding replay is verification, not exploitation: it must never change target state.
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class FindingVerifier:
    """Replays ``repro`` and returns ``(verified, note)``."""

    def verify(self, repro: dict[str, Any], ctx: ToolContext) -> tuple[bool, str]:
        req_spec = repro.get("request") or {}
        url = str(req_spec.get("url", "")).strip()
        if not url:
            return False, "repro has no request.url"

        method = str(req_spec.get("method", "GET")).upper()
        if method not in _SAFE_METHODS:
            note = (
                f"refused to replay {method} {url}: finding verification is read-only "
                f"(allowed: {', '.join(sorted(_SAFE_METHODS))}). Route a state-changing proof "
                "through the operator approval flow instead."
            )
            self._audit(ctx, method, url, status=None, ok=False, note=note)
            return False, note

        try:
            require_authorized(url, ctx)
        except PermissionError as exc:
            note = f"repro target off-scope: {exc}"
            self._audit(ctx, method, url, status=None, ok=False, note=note)
            return False, note

        blocked = self._policy_block(url, ctx)
        if blocked:
            self._audit(ctx, method, url, status=None, ok=False, note=blocked)
            return False, blocked

        headers = {str(k): str(v) for k, v in (req_spec.get("headers") or {}).items()}
        body = req_spec.get("body")
        data = body.encode("utf-8") if isinstance(body, str) and body else None
        req = Request(url, data=data, headers=headers, method=method)  # noqa: S310 - gated above

        acquired = self._limiter_before(ctx, method, url)
        try:
            with session_of(ctx).open(req, _TIMEOUT) as resp:
                status = resp.status
                text = resp.read(_MAX_BODY).decode("utf-8", "replace")
        except HTTPError as exc:  # a 4xx/5xx is a real result the expectation may target
            status = exc.code
            text = exc.read(_MAX_BODY).decode("utf-8", "replace") if exc.fp else ""
        except Exception as exc:  # noqa: BLE001 - transport failure => unverified, not a crash
            note = f"replay failed: {type(exc).__name__}: {exc}"
            self._audit(ctx, method, url, status=None, ok=False, note=note)
            return False, note
        finally:
            self._limiter_after(ctx, acquired)

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
            note = (
                f"replayed {method} {url} -> HTTP {status}; no explicit expect or "
                "expect_status supplied (unverified)"
            )
            self._audit(ctx, method, url, status=status, ok=False, note=note)
            return False, note
        verdict = "confirmed" if ok else "NOT reproduced"
        note = f"replayed {method} {url} -> HTTP {status}; " + "; ".join(checks) + f" ({verdict})"
        self._audit(ctx, method, url, status=status, ok=ok, note=note)
        return ok, note

    # ── gating collaborators (all optional; degrade cleanly when absent) ──────────────

    @staticmethod
    def _policy_block(url: str, ctx: ToolContext) -> str:
        """Evaluate the replay against the RoE action policy. Returns a reason if refused.

        The replay is a read-only GET/HEAD/OPTIONS (enforced above), so it is classified as
        passive reconnaissance and only a hard ``prohibit`` (out of scope, outside the testing
        window, on an exclusion list) refuses it. A ``require_approval`` disposition must NOT block
        verification: gating a read-only reproduction of an already-recorded finding behind manual
        approval would silently disable verification for every RoE-configured run.
        """
        roe = getattr(ctx, "rules_of_engagement", None)
        if roe is None:
            return ""
        from ai_framework.harness.contracts import (
            ActionClass,
            ActionDisposition,
            ActionRequest,
        )
        from ai_framework.harness.policy import evaluate_action

        request = ActionRequest(
            action_class=ActionClass.passive_reconnaissance,
            target=url,
            summary="finding-verification replay (read-only)",
        )
        try:
            decision = evaluate_action(
                roe, request, primary_target=getattr(ctx, "primary_target", "")
            )
        except Exception as exc:  # noqa: BLE001 - fail closed: a policy-eval error blocks the replay
            return f"finding-verification replay blocked (policy evaluation error: {exc})"
        if decision.disposition == ActionDisposition.prohibit:
            return "finding-verification replay blocked by RoE: " + "; ".join(decision.reasons)
        return ""

    @staticmethod
    def _limiter_before(ctx: ToolContext, method: str, url: str) -> bool:
        limiter = getattr(ctx, "limiter", None)
        if limiter is None:
            return False
        call = SimpleNamespace(name="finding_verify_replay", arguments={"url": url})
        tool = SimpleNamespace(touches_network=True)
        try:
            return bool(limiter.before(call, tool))
        except Exception:  # noqa: BLE001 - a limiter failure must not crash verification
            return False

    @staticmethod
    def _limiter_after(ctx: ToolContext, acquired: bool) -> None:
        limiter = getattr(ctx, "limiter", None)
        if limiter is not None:
            limiter.after(acquired)

    @staticmethod
    def _audit(
        ctx: ToolContext, method: str, url: str, status: int | None, ok: bool, note: str
    ) -> None:
        audit = getattr(ctx, "audit", None)
        if audit is None:
            return
        try:
            audit.append(
                "finding_verify",
                {
                    "run_id": getattr(ctx, "run_id", ""),
                    "method": method,
                    "url": url,
                    "status": status,
                    "ok": ok,
                    "note": note,
                },
            )
        except Exception:  # noqa: BLE001 - audit best-effort; never break verification
            pass
