"""Minimal stdlib HTTP API over RunService — no web-framework dependency.

Two ways to run:

* **Dev** (``python -m backend.app``) — API only on ``127.0.0.1:61021``. The Vite dev
  server (``:61020``) proxies ``/api/*`` here, so API routes are unprefixed (``/runs``).
* **Packaged** (the ``secforge`` launcher) — pass ``static_root`` pointing at the built
  frontend (``frontend/dist``). One server then serves the Web UI *and* the API on a
  single port (``:61022``). The frontend calls ``/api/*``; this handler strips that prefix,
  so the same routes serve both modes.

API routes (with or without the ``/api`` prefix):
    POST /runs                 body: {goal, target, backend?, model?, step_budget?,
                                      authorized_targets?, opsec_min_interval?, opsec_jitter?}
                                      -> 201 {"id": ...}
    GET  /runs                 -> 200 {"runs": [summaries]}    (persisted run history)
    GET  /runs/{id}            -> 200 <Run JSON> | 404   (outcome=="incomplete" => running)
    GET  /runs/{id}/report?format=md|json -> 200 report | 404  (findings as pentest report)
    POST /runs/{id}/stop       -> 200 {ok} | 409  (Stop button — signal the loop to end)
    POST /campaigns            body: {domain, backend?, model?, authorized_targets?,
                                      phase_step_budget?, autopilot?, max_phases?,
                                      auto_approve_mutating?} -> 201 {"id": ...}  (continuous run)
    POST /pentest              body: {target|domain, backend?, model?, authorized_targets?,
                                      max_phases?, auto_approve_mutating?} -> 201 {"id": ...}
                                      (one-shot AUTONOMOUS pentest: just give an address)
    GET  /campaigns            -> 200 {"campaigns": [summaries]}
    GET  /campaigns/{id}       -> 200 <Campaign JSON + phase_runs> | 404
    POST /campaigns/{id}/continue|stop           -> 200 {"ok": bool} | 409
    POST /campaigns/{id}/approve|reject  body: {approval_id} -> 200 {"ok": bool} | 409
    GET  /findings?target=...  -> 200 {total, by_severity, targets, recent}
    GET  /assets?target=...    -> 200 {total, by_kind, values, targets, recent}  (recon graph)
    GET    /provider-types     -> 200 [catalog presets: id,label,category,base_url,auth,...]
    GET    /accounts           -> 200 {policy, accounts:[masked + health]}
    POST   /accounts           -> 201 {account}            body: {label, base_url, api_key, ...}
    PATCH  /accounts/{id}      -> 200 {account} | 404      body: partial fields
    DELETE /accounts/{id}      -> 200 {ok} | 404
    GET    /accounts/{id}/models -> 200 {models:[...]}
    GET    /accounts/export -> 200 {version, policy, accounts:[...]}  (credential-free backup)
    POST   /accounts/import    -> 200 {added, skipped} | 400   body: {accounts:[...], mode?}
    GET    /usage              -> 200 {accounts:[{id,label,limits,total,today,health}]}  (quota)
    POST   /usage/reset        -> 200 {ok}                 body: {account_id?}  (all when absent)
    GET    /models             -> 200 {accounts:[...], catalog:[{provider,label,models}]}
    POST   /accounts/{id}/test -> 200 {ok, status, error?} | 404   (live probe, stored key)
    POST   /probe-models       -> 200 {models:[...]}       body: {base_url, api_key?}
    POST   /test-connection    -> 200 {ok,status,error?} body: {base_url,api_key?,model?,api_style?}
    GET    /oauth/providers    -> 200 {id: {flow, supported, reason}}   (sign-in flow metadata)
    POST   /oauth/start        -> 200 <device|pkce session> | 400       body: {provider}
    POST   /oauth/poll         -> 200 {status:pending} | {status:done, account}  body: {session_id}
    POST   /oauth/complete     -> 201 {status:done, account} | 400      body: {session_id, code}
    POST   /router/policy      -> 200 {policy} | 400       body: {policy}
    GET    /memory?target=...  -> 200 {total, by_kind, targets, recent}

    -- Expert Supervisor + Hermes notebook (the default advisory flow; never calls an AI
       provider or executes anything against a target) --
    POST  /supervisor/advise   body: {domain, question, mode?, project_path?, scan_mode?,
                                      vendor?, rules_of_engagement?}
                                      -> 200 {domain, archetype, plan, skills, questions,
                                              harness, context_block}
                                      (scan_mode: quick|standard|deep, default standard)
    GET   /taxonomy            -> 200 {tree}                       (shared category->technique tree)
    GET   /archetypes          -> 200 {archetypes}                 (seeded + user-saved heuristics)
    GET   /notebooks           -> 200 {notebooks}                  (flat domain summaries)
    GET   /notebooks/tree      -> 200 {roots}                      (nested root -> subdomain tree)
    GET   /notebook/{domain}          -> 200 <Notebook JSON>       (created on first /advise call)
    GET   /notebook/{domain}/tree     -> 200 {domain, tree}        (taxonomy + per-node status,
                                                                     incl. a synthetic "others"
                                                                     category for custom findings)
    GET   /notebook/{domain}/sarif    -> 200 <SARIF 2.1.0 JSON>    (confirmed/unconfirmed nodes
                                                                     as code-scanning results,
                                                                     for CI upload)
    PATCH /notebook/{domain}          body: {node_id, status, note?, finding?} -> 200 <Notebook>
                                       body: {node_id, in_progress: true}      -> 200 <Notebook>
                                                                     (manual "testing this now"
                                                                      flag — set automatically
                                                                      by /advise too)
    PATCH /notebook/{domain}/archetype body: {archetype}           -> 200 <Notebook>
    POST  /notebook/{domain}/ingest   body: {text}                 -> {notebook, promoted,
                                                                        custom_added}
                                                                     (paste an external agent's raw
                                                                      output; stored verbatim, then
                                                                      parsed for CONFIRMED/
                                                                      NEW_FINDING_TYPE markers)
    POST  /notebook/{domain}/children body: {child}                -> 201 <Notebook> (attach a
                                                                     discovered subdomain under
                                                                     its parent)
    POST  /notebook/{domain}/chains   body: {from_node, to_node, note?} -> 201 <Notebook>
                                                                     (record an exploit-chain step)
    DELETE /notebook/{domain}         -> 200 {ok: true} | 404        (permanently removes that
                                                                     domain's notebook; does not
                                                                     cascade to its subdomains)

    NOTE: /runs, /campaigns, and /pentest below execute the *legacy autonomous engine* and are
    disabled (403) unless SECFORGE_ENABLE_AUTONOMOUS=1 — SecForge no longer executes pentest
    actions itself by default; use /supervisor/advise and hand the result to your own coding
    agent (e.g. Claude Code) instead. Continuous campaigns stay locked pending a redesign.
    GET    /kb?locale=         -> 200 {total, categories}        (knowledge base list)
    GET    /kb/doc/{id}?locale= -> 200 {id, title, html, toc} | 404
    GET    /kb/search?q=&mode=&locale= -> 200 {hits}             (mode=full|errors)
    GET    /vuln-search?q=&online=&locale= -> 200 {techniques, cves}
    POST   /defense/review     -> 200 <DefenseReport> | 400      body: {path}
    POST   /defense/scan       -> 200 {code_review, dependencies, campaign_id?} | 400
                                  body: {path, deps_online?, serve_url?, backend?, model?}
                                  (code signatures + SCA; optional live attack of a running app)
    GET    /i18n/{locale}      -> 200 {locale, available, strings, glossary}

Any non-API GET falls through to ``static_root`` (SPA: unknown paths return index.html).
Host/port via SECFORGE_API_HOST / SECFORGE_API_PORT.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from ai_framework.agent.campaign import CampaignConfig
from ai_framework.agent.contracts import RunConfig
from ai_framework.router.accounts import Account
from ai_framework.router.oauth import PROVIDERS as OAUTH_PROVIDERS
from ai_framework.router.oauth import OAuthError, OAuthManager
from ai_framework.router.router import health_snapshot
from ai_framework.security.redaction import redact_data, redact_text
from backend.providers import PROVIDER_TYPES, check_endpoint, probe_models
from backend.service import AutonomousDisabledError, RunService

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 61021  # dev (API-only). The packaged launcher binds 61022 with static_root.
_MAX_API_BODY = 2 * 1024 * 1024


def _is_loopback(value: str) -> bool:
    host = value.strip().lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _header_host(value: str) -> str:
    parsed = urlparse("//" + value.strip())
    return (parsed.hostname or "").lower()


def _router_view(service: RunService) -> dict[str, Any]:
    health = health_snapshot()
    accounts = [
        {**a.masked(), "health": health.get(a.id, {})} for a in service.accounts.list_accounts()
    ]
    return {"policy": service.accounts.get_policy(), "accounts": accounts}


def _usage_view(service: RunService) -> dict[str, Any]:
    """Per-account quota view: persisted usage (calls + tokens) + limits + live health."""
    usage = service.usage.snapshot()
    health = health_snapshot()
    accounts = []
    for a in service.accounts.list_accounts():
        u = usage.get(a.id, {})
        accounts.append({
            "id": a.id, "label": a.label, "kind": a.kind, "tier": a.tier,
            "enabled": a.enabled, "model": a.model,
            "limits": {
                "daily_requests": a.quota_daily_requests,
                "daily_tokens": a.quota_daily_tokens,
            },
            "total": u.get("total", {}),
            "today": u.get("today", {}),
            "first_used": u.get("first_used", ""),
            "last_used": u.get("last_used", ""),
            "health": health.get(a.id, {}),
        })
    return {"accounts": accounts}


def _models_view(service: RunService) -> dict[str, Any]:
    """Pool-wide model overview: each account's current model + the catalog's suggestions.

    Live per-account model lists stay on-demand (``GET /accounts/{id}/models``) so this stays a
    cheap, network-free response the Models popup can render instantly.
    """
    accounts = [
        {"id": a.id, "label": a.label, "kind": a.kind, "model": a.model,
         "api_style": a.api_style, "enabled": a.enabled, "base_url": a.base_url}
        for a in service.accounts.list_accounts()
    ]
    catalog = [
        {"provider": p["id"], "label": p["label"], "models": p["models"]}
        for p in PROVIDER_TYPES if p.get("models")
    ]
    return {"accounts": accounts, "catalog": catalog}


def _export_accounts(service: RunService) -> dict[str, Any]:
    """Serialize a credential-free account preset for download/backup."""
    rows = []
    for a in service.accounts.list_accounts():
        row = a.model_dump()
        row["api_key"] = ""
        row["refresh_token"] = ""
        row["provider_data"] = {}
        rows.append(row)
    return {
        "version": 1,
        "kind": "secforge-accounts",
        "include_keys": False,
        "policy": service.accounts.get_policy(),
        "accounts": rows,
    }


def _import_accounts(service: RunService, rows: Any, mode: str) -> dict[str, Any]:
    """Add accounts from an uploaded export. ``replace`` clears the pool first; ``merge`` dedupes
    on (kind, base_url, label). Incoming ids are dropped so imports never collide."""
    if not isinstance(rows, list):
        raise ValueError("'accounts' must be a list")
    if mode == "replace":
        for a in service.accounts.list_accounts():
            service.accounts.remove(a.id)
    seen = {(a.kind, a.base_url, a.label) for a in service.accounts.list_accounts()}
    added, skipped = 0, 0
    for row in rows:
        if not isinstance(row, dict):
            skipped += 1
            continue
        fields = {k: v for k, v in row.items() if k != "id"}  # fresh id on import
        try:
            account = Account.model_validate(fields)
        except Exception:  # noqa: BLE001 - a malformed row is skipped, not fatal
            skipped += 1
            continue
        key = (account.kind, account.base_url, account.label)
        if key in seen:
            skipped += 1
            continue
        service.accounts.add(account)
        seen.add(key)
        added += 1
    return {"added": added, "skipped": skipped}


def _strip_api_prefix(path: str) -> str:
    """Map a ``/api``-prefixed request (packaged mode) to a bare API route."""
    if path == "/api":
        return "/"
    if path.startswith("/api/"):
        return path[len("/api") :]
    return path


def _provider_label(kind: str) -> str:
    """Human label for a provider id (falls back to the id itself)."""
    return next((p["label"] for p in PROVIDER_TYPES if p["id"] == kind), kind)


def make_handler(
    service: RunService, static_root: Path | None = None, api_token: str | None = None
) -> type[BaseHTTPRequestHandler]:
    root = static_root.resolve() if static_root else None
    configured_token = api_token if api_token is not None else os.getenv("SECFORGE_API_TOKEN", "")
    # One OAuth manager per server so pending sign-in sessions survive across requests.
    oauth = OAuthManager()

    def _create_oauth_account(fields: dict[str, Any], label: str) -> dict[str, Any]:
        account = Account(label=label or _provider_label(fields.get("kind", "")), **fields)
        service.accounts.add(account)
        return account.masked()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload: Any) -> None:
            body = (payload if isinstance(payload, str) else json.dumps(payload)).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", 0))
            if length > _MAX_API_BODY:
                raise ValueError(f"request body exceeds {_MAX_API_BODY} bytes")
            return json.loads(self.rfile.read(length) or b"{}")

        def _authorize_request(self) -> bool:
            """Protect the localhost control plane from exposure and DNS-rebinding access."""
            peer = str(self.client_address[0])
            supplied = self.headers.get("Authorization", "")
            expected = f"Bearer {configured_token}" if configured_token else ""
            token_ok = bool(expected) and hmac.compare_digest(supplied, expected)
            if token_ok:
                return True
            if configured_token:
                self._send(401, {"error": "missing or invalid API bearer token"})
                return False
            host_is_local = _is_loopback(_header_host(self.headers.get("Host", "")))
            if not _is_loopback(peer) or not host_is_local:
                self._send(403, {"error": "local API accepts loopback requests only"})
                return False
            origin = self.headers.get("Origin", "").strip()
            if origin and not _is_loopback(urlparse(origin).hostname or ""):
                self._send(403, {"error": "cross-origin request rejected"})
                return False
            return True

        # ── POST ──
        def _post_impl(self) -> None:
            path = _strip_api_prefix(urlparse(self.path).path)
            if path == "/supervisor/advise":
                b = self._body()
                try:
                    result = service.advise(
                        domain=b.get("domain", ""),
                        question=b.get("question", ""),
                        mode=b.get("mode", "blackbox"),
                        project_path=b.get("project_path"),
                        scan_mode=b.get("scan_mode", "standard"),
                        vendor=b.get("vendor", "generic"),
                        rules_of_engagement=b.get("rules_of_engagement"),
                    )
                except Exception as exc:  # noqa: BLE001
                    return self._send(400, {"error": str(exc)})
                return self._send(200, result)
            if path == "/runs":
                try:
                    config = RunConfig.model_validate(self._body())
                except Exception as exc:  # noqa: BLE001
                    return self._send(400, {"error": str(exc)})
                try:
                    return self._send(201, {"id": service.start_run(config)})
                except (AutonomousDisabledError, PermissionError) as exc:
                    return self._send(403, {"error": str(exc)})
            if path.startswith("/runs/") and path.endswith("/stop"):
                rid = path[len("/runs/") : -len("/stop")]
                ok = service.stop_run(rid)
                return self._send(200 if ok else 409, {"ok": ok})
            if path == "/campaigns":
                try:
                    cfg = CampaignConfig.model_validate(self._body())
                except Exception as exc:  # noqa: BLE001
                    return self._send(400, {"error": str(exc)})
                try:
                    return self._send(201, {"id": service.start_campaign(cfg)})
                except (AutonomousDisabledError, PermissionError) as exc:
                    return self._send(403, {"error": str(exc)})
            if path == "/pentest":
                # One-shot autonomous pentest: caller supplies only an address. Accept it under
                # either "target" or "domain"; autopilot is forced on so a single request drives
                # the whole engagement to a stop condition.
                body = self._body()
                body.setdefault("domain", body.get("target", ""))
                try:
                    cfg = CampaignConfig.model_validate(body)
                except Exception as exc:  # noqa: BLE001
                    return self._send(400, {"error": str(exc)})
                try:
                    return self._send(201, {"id": service.start_pentest(cfg)})
                except (AutonomousDisabledError, PermissionError) as exc:
                    return self._send(403, {"error": str(exc)})
            if path.startswith("/campaigns/"):
                rest = path[len("/campaigns/") :]
                body = self._body()
                cid, _, action = rest.partition("/")
                if action == "continue":
                    ok = service.continue_campaign(cid)
                elif action == "stop":
                    ok = service.stop_campaign(cid)
                elif action == "approve":
                    ok = service.approve_action(cid, body.get("approval_id", ""))
                elif action == "reject":
                    ok = service.reject_action(cid, body.get("approval_id", ""))
                else:
                    return self._send(404, {"error": "unknown campaign action"})
                return self._send(200 if ok else 409, {"ok": ok})
            if path == "/accounts":
                try:
                    account = Account.model_validate(self._body())
                except Exception as exc:  # noqa: BLE001
                    return self._send(400, {"error": str(exc)})
                service.accounts.add(account)
                return self._send(201, account.masked())
            if path == "/accounts/import":
                b = self._body()
                try:
                    result = _import_accounts(
                        service, b.get("accounts"), b.get("mode", "merge")
                    )
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
                return self._send(200, result)
            if path == "/usage/reset":
                service.usage.reset(self._body().get("account_id") or None)
                return self._send(200, {"ok": True})
            if path == "/probe-models":
                b = self._body()
                models = probe_models(b.get("base_url", ""), b.get("api_key", ""))
                return self._send(200, {"models": models})
            if path == "/test-connection":
                b = self._body()
                return self._send(
                    200,
                    check_endpoint(
                        b.get("base_url", ""),
                        b.get("api_key", ""),
                        b.get("model", ""),
                        api_style=b.get("api_style", "openai"),
                    ),
                )
            if path.startswith("/accounts/") and path.endswith("/test"):
                self._body()  # drain the request body so the socket isn't reset on 404
                aid = path[len("/accounts/") : -len("/test")]
                acct = service.accounts.get(aid)
                if not acct:
                    return self._send(404, {"error": "unknown account"})
                return self._send(
                    200,
                    check_endpoint(
                        acct.base_url, acct.api_key, acct.model, api_style=acct.api_style
                    ),
                )
            # ── OAuth sign-in flows ──
            if path == "/oauth/start":
                b = self._body()
                try:
                    return self._send(
                        200, oauth.start(b.get("provider", ""), b.get("model", ""))
                    )
                except OAuthError as exc:
                    return self._send(400, {"error": str(exc)})
            if path == "/oauth/poll":
                b = self._body()
                try:
                    result = oauth.poll(b.get("session_id", ""))
                except OAuthError as exc:
                    return self._send(400, {"error": str(exc)})
                if result.get("status") == "done":
                    masked = _create_oauth_account(result["account"], b.get("label", ""))
                    result = {"status": "done", "account": masked}
                return self._send(200, result)
            if path == "/oauth/complete":
                b = self._body()
                try:
                    result = oauth.complete(b.get("session_id", ""), b.get("code", ""))
                except OAuthError as exc:
                    return self._send(400, {"error": str(exc)})
                masked = _create_oauth_account(result["account"], b.get("label", ""))
                return self._send(201, {"status": "done", "account": masked})
            if path == "/oauth/import":
                # Non-interactive connect: paste a refresh token or an API key (e.g. Kiro).
                b = self._body()
                provider = b.get("provider", "")
                method = b.get("method", "import")
                try:
                    if method == "api_key":
                        result = oauth.import_api_key(
                            provider, b.get("api_key", ""), b.get("region", "us-east-1"),
                            b.get("model", ""),
                        )
                    else:
                        result = oauth.import_token(
                            provider, b.get("token", ""), b.get("model", "")
                        )
                except OAuthError as exc:
                    return self._send(400, {"error": str(exc)})
                masked = _create_oauth_account(result["account"], b.get("label", ""))
                return self._send(201, {"status": "done", "account": masked})
            if path == "/router/policy":
                try:
                    policy = service.accounts.set_policy(self._body()["policy"])
                    return self._send(200, {"policy": policy})
                except Exception as exc:  # noqa: BLE001
                    return self._send(400, {"error": str(exc)})
            if path == "/defense/review":
                target = self._body().get("path", "")
                if not target:
                    return self._send(400, {"error": "missing 'path'"})
                report = service.pillars.defense_review(target)
                return self._send(400 if "error" in report else 200, report)
            if path == "/defense/scan":
                # Combined assessment: code signatures + dependency (SCA) inventory, plus an
                # optional live attack of the running app when ``serve_url`` is supplied.
                body = self._body()
                target = body.get("path", "")
                if not target:
                    return self._send(400, {"error": "missing 'path'"})
                report = service.defense_autopilot(
                    target,
                    serve_url=body.get("serve_url") or None,
                    deps_online=bool(body.get("deps_online", False)),
                    backend=body.get("backend", "offline"),
                    model=body.get("model"),
                    base_url=body.get("base_url"),
                    authorized_targets=set(body.get("authorized_targets", []) or []),
                )
                return self._send(400 if "error" in report else 200, report)
            if path.startswith("/notebook/") and path.endswith("/ingest"):
                domain = unquote(path[len("/notebook/") : -len("/ingest")].rstrip("/"))
                text = self._body().get("text", "")
                return self._send(200, service.ingest_notebook_output(domain, text))
            if path.startswith("/notebook/") and path.endswith("/children"):
                domain = unquote(path[len("/notebook/") : -len("/children")].rstrip("/"))
                b = self._body()
                child = b.get("child", "")
                if not child:
                    return self._send(400, {"error": "missing 'child'"})
                return self._send(201, service.add_notebook_child(domain, child))
            if path.startswith("/notebook/") and path.endswith("/chains"):
                domain = unquote(path[len("/notebook/") : -len("/chains")].rstrip("/"))
                b = self._body()
                from_node, to_node = b.get("from_node", ""), b.get("to_node", "")
                if not from_node or not to_node:
                    return self._send(400, {"error": "missing 'from_node'/'to_node'"})
                return self._send(
                    201,
                    service.add_notebook_chain(domain, from_node, to_node, note=b.get("note", "")),
                )
            return self._send(404, {"error": "not found"})

        # ── PATCH ──
        def _patch_impl(self) -> None:
            path = _strip_api_prefix(urlparse(self.path).path)
            if path.startswith("/accounts/"):
                acct = service.accounts.update(path.removeprefix("/accounts/"), self._body())
                if not acct:
                    return self._send(404, {"error": "unknown account"})
                return self._send(200, acct.masked())
            if path.startswith("/notebook/") and path.endswith("/archetype"):
                domain = unquote(path[len("/notebook/") : -len("/archetype")].rstrip("/"))
                archetype = self._body().get("archetype", "")
                return self._send(200, service.set_notebook_archetype(domain, archetype))
            if path.startswith("/notebook/"):
                domain = unquote(path.removeprefix("/notebook/"))
                b = self._body()
                if b.get("in_progress") is True and "status" not in b:
                    return self._send(
                        200, service.mark_notebook_in_progress(domain, b.get("node_id", ""))
                    )
                try:
                    result = service.update_notebook_node(
                        domain,
                        b.get("node_id", ""),
                        b.get("status", "untested"),
                        note=b.get("note", ""),
                        finding=b.get("finding"),
                        severity=b.get("severity", ""),
                    )
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
                return self._send(200, result)
            return self._send(404, {"error": "not found"})

        # ── DELETE ──
        def _delete_impl(self) -> None:
            path = _strip_api_prefix(urlparse(self.path).path)
            if path.startswith("/accounts/"):
                ok = service.accounts.remove(path.removeprefix("/accounts/"))
                if not ok:
                    return self._send(404, {"error": "unknown account"})
                return self._send(200, {"ok": True})
            if path.startswith("/notebook/"):
                domain = unquote(path.removeprefix("/notebook/"))
                ok = service.delete_notebook_domain(domain)
                if not ok:
                    return self._send(404, {"error": "unknown domain"})
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})

        # ── GET ──
        def _get_impl(self) -> None:
            parsed = urlparse(self.path)
            path = _strip_api_prefix(parsed.path)
            if path == "/provider-types":
                return self._send(200, PROVIDER_TYPES)
            if path == "/oauth/providers":
                return self._send(200, {
                    pid: {"flow": p.flow, "supported": p.supported,
                          "reason": p.unsupported_reason, "methods": list(p.methods)}
                    for pid, p in OAUTH_PROVIDERS.items()
                })
            if path == "/accounts":
                return self._send(200, _router_view(service))
            if path == "/accounts/export":
                inc = (parse_qs(parsed.query).get("include_keys") or ["0"])[0]
                include_keys = inc in {"1", "true", "yes"}
                if include_keys:
                    return self._send(
                        403,
                        {"error": "secret export is disabled; use the encrypted account store"},
                    )
                return self._send(200, _export_accounts(service))
            if path == "/usage":
                return self._send(200, _usage_view(service))
            if path == "/models":
                return self._send(200, _models_view(service))
            if path.startswith("/accounts/") and path.endswith("/models"):
                aid = path[len("/accounts/") : -len("/models")]
                acct = service.accounts.get(aid)
                if not acct:
                    return self._send(404, {"error": "unknown account"})
                return self._send(200, {"models": probe_models(acct.base_url, acct.api_key)})
            if path == "/memory":
                target = (parse_qs(parsed.query).get("target") or [""])[0]
                return self._send(200, service.memory_summary(target))
            if path == "/taxonomy":
                return self._send(200, {"tree": service.get_taxonomy_tree()})
            if path == "/archetypes":
                return self._send(200, {"archetypes": service.list_archetypes()})
            if path == "/notebooks":
                return self._send(200, {"notebooks": service.list_notebook_domains()})
            if path == "/notebooks/tree":
                return self._send(200, {"roots": service.list_notebook_tree_roots()})
            if path.startswith("/notebook/") and path.endswith("/tree"):
                domain = unquote(path[len("/notebook/") : -len("/tree")].rstrip("/"))
                return self._send(200, service.get_notebook_tree(domain))
            if path.startswith("/notebook/") and path.endswith("/sarif"):
                domain = unquote(path[len("/notebook/") : -len("/sarif")].rstrip("/"))
                return self._send(200, service.notebook_sarif(domain))
            if path.startswith("/notebook/"):
                domain = unquote(path.removeprefix("/notebook/"))
                return self._send(200, service.get_notebook(domain))
            # ── pillars (knowledge base / vuln search / i18n) ──
            query = parse_qs(parsed.query)
            locale = (query.get("locale") or ["en"])[0]
            if path == "/kb":
                return self._send(200, service.pillars.kb_list(locale))
            if path.startswith("/kb/doc/"):
                doc_id = unquote(path.removeprefix("/kb/doc/"))
                doc = service.pillars.kb_doc(doc_id, locale)
                return self._send(200, doc) if doc else self._send(404, {"error": "unknown doc"})
            if path == "/kb/search":
                q = (query.get("q") or [""])[0]
                mode = (query.get("mode") or ["full"])[0]
                return self._send(200, service.pillars.kb_search(q, mode, locale))
            if path == "/vuln-search":
                q = (query.get("q") or [""])[0]
                online = (query.get("online") or ["0"])[0] in {"1", "true", "yes"}
                return self._send(200, service.pillars.vuln_search(q, online, locale))
            if path.startswith("/i18n/"):
                return self._send(200, service.pillars.i18n(path.removeprefix("/i18n/")))
            if path == "/campaigns":
                return self._send(200, {"campaigns": service.list_campaigns()})
            if path.startswith("/campaigns/"):
                campaign = service.get_campaign(path.removeprefix("/campaigns/"))
                if campaign is None:
                    return self._send(404, {"error": "unknown campaign id"})
                return self._send(200, redact_data(campaign))
            if path == "/runs":
                return self._send(200, {"runs": service.list_runs()})
            if path == "/findings":
                target = (query.get("target") or [""])[0]
                return self._send(200, service.findings_summary(target))
            if path == "/assets":
                target = (query.get("target") or [""])[0]
                return self._send(200, service.assets_summary(target))
            if path == "/evidence/verify":
                return self._send(200, service.evidence_status())
            if path.startswith("/runs/") and path.endswith("/report"):
                rid = path[len("/runs/") : -len("/report")]
                fmt = (query.get("format") or ["md"])[0]
                report = service.run_report(rid, fmt)
                if report is None:
                    return self._send(404, {"error": "unknown run id"})
                clean = redact_data(report)
                payload = clean if fmt == "json" else {"format": "md", "report": clean}
                return self._send(200, payload)
            if path.startswith("/runs/"):
                run = service.get_run(path.removeprefix("/runs/"))
                if not run:
                    return self._send(404, {"error": "unknown run id"})
                return self._send(200, redact_data(run.model_dump(mode="json")))
            # Non-API GET → static frontend (packaged mode), else 404.
            if root is not None:
                return self._serve_static(parsed.path)
            return self._send(404, {"error": "not found"})

        # ── static frontend (SPA) ──
        def _serve_static(self, url_path: str) -> None:
            assert root is not None
            rel = unquote(url_path).lstrip("/") or "index.html"
            target = (root / rel).resolve()
            # Block path traversal: the resolved file must stay inside root.
            if root not in target.parents and target != root:
                return self._send(403, {"error": "forbidden"})
            if not target.is_file():
                target = root / "index.html"  # SPA fallback for client-side routes
            if not target.is_file():
                return self._send(
                    404, {"error": "frontend not built (run npm run build in frontend/)"}
                )
            data = target.read_bytes()
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        # ── dispatch: every verb is guarded so a bug always answers JSON, never a raw
        # http.server error page (which broke the frontend's error parsing and looked like
        # every provider had vanished, when only one endpoint's response body wasn't JSON).
        def _guarded(self, impl: Any) -> None:
            try:
                if not self._authorize_request():
                    return
                impl()
            except Exception as exc:  # noqa: BLE001 - last-resort handler, must not re-raise
                message = redact_text(f"{type(exc).__name__}: {exc}")
                self._send(500, redact_data({"error": message}))

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            self._guarded(self._get_impl)

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            self._guarded(self._post_impl)

        def do_PATCH(self) -> None:  # noqa: N802 - http.server API
            self._guarded(self._patch_impl)

        def do_DELETE(self) -> None:  # noqa: N802 - http.server API
            self._guarded(self._delete_impl)

        def log_message(self, *args: object) -> None:
            pass

    return Handler


def build_server(
    service: RunService,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    static_root: Path | None = None,
) -> ThreadingHTTPServer:
    """Construct (but don't start) the threaded HTTP server."""
    token = os.getenv("SECFORGE_API_TOKEN", "").strip()
    if not _is_loopback(host) and not token:
        raise RuntimeError(
            "non-loopback API binding requires SECFORGE_API_TOKEN; refusing insecure exposure"
        )
    return ThreadingHTTPServer((host, port), make_handler(service, static_root, token))


def main() -> None:
    host = os.getenv("SECFORGE_API_HOST", DEFAULT_HOST)
    port = int(os.getenv("SECFORGE_API_PORT", str(DEFAULT_PORT)))
    server = build_server(RunService(), host, port)
    print(f"SecForge API on http://{host}:{port}  (runs, /accounts router, /memory)")
    server.serve_forever()


if __name__ == "__main__":
    main()
