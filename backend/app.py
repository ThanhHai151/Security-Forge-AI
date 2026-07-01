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
    GET  /findings?target=...  -> 200 {total, by_severity, targets, recent}
    GET    /provider-types     -> 200 [catalog presets: id,label,category,base_url,auth,...]
    GET    /accounts           -> 200 {policy, accounts:[masked + health]}
    POST   /accounts           -> 201 {account}            body: {label, base_url, api_key, ...}
    PATCH  /accounts/{id}      -> 200 {account} | 404      body: partial fields
    DELETE /accounts/{id}      -> 200 {ok} | 404
    GET    /accounts/{id}/models -> 200 {models:[...]}
    POST   /accounts/{id}/test -> 200 {ok, status, error?} | 404   (live probe, stored key)
    POST   /probe-models       -> 200 {models:[...]}       body: {base_url, api_key?}
    POST   /test-connection    -> 200 {ok,status,error?} body: {base_url,api_key?,model?,api_style?}
    GET    /oauth/providers    -> 200 {id: {flow, supported, reason}}   (sign-in flow metadata)
    POST   /oauth/start        -> 200 <device|pkce session> | 400       body: {provider}
    POST   /oauth/poll         -> 200 {status:pending} | {status:done, account}  body: {session_id}
    POST   /oauth/complete     -> 201 {status:done, account} | 400      body: {session_id, code}
    POST   /router/policy      -> 200 {policy} | 400       body: {policy}
    GET    /memory?target=...  -> 200 {total, by_kind, targets, recent}
    GET    /kb?locale=         -> 200 {total, categories}        (knowledge base list)
    GET    /kb/doc/{id}?locale= -> 200 {id, title, html, toc} | 404
    GET    /kb/search?q=&mode=&locale= -> 200 {hits}             (mode=full|errors)
    GET    /vuln-search?q=&online=&locale= -> 200 {techniques, cves}
    POST   /defense/review     -> 200 <DefenseReport> | 400      body: {path}
    GET    /labs               -> 200 {labs:[meta + solved]}     (metadata only)
    GET    /i18n/{locale}      -> 200 {locale, available, strings, glossary}

Any non-API GET falls through to ``static_root`` (SPA: unknown paths return index.html).
Host/port via SECFORGE_API_HOST / SECFORGE_API_PORT.
"""

from __future__ import annotations

import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from ai_framework.agent.contracts import RunConfig
from ai_framework.router.accounts import Account
from ai_framework.router.oauth import PROVIDERS as OAUTH_PROVIDERS
from ai_framework.router.oauth import OAuthError, OAuthManager
from ai_framework.router.router import health_snapshot
from backend.providers import PROVIDER_TYPES, check_endpoint, probe_models
from backend.service import RunService

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 61021  # dev (API-only). The packaged launcher binds 61022 with static_root.


def _router_view(service: RunService) -> dict[str, Any]:
    health = health_snapshot()
    accounts = [
        {**a.masked(), "health": health.get(a.id, {})} for a in service.accounts.list_accounts()
    ]
    return {"policy": service.accounts.get_policy(), "accounts": accounts}


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
    service: RunService, static_root: Path | None = None
) -> type[BaseHTTPRequestHandler]:
    root = static_root.resolve() if static_root else None
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
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length) or b"{}")

        # ── POST ──
        def do_POST(self) -> None:  # noqa: N802 - http.server API
            path = _strip_api_prefix(urlparse(self.path).path)
            if path == "/runs":
                try:
                    config = RunConfig.model_validate(self._body())
                except Exception as exc:  # noqa: BLE001
                    return self._send(400, {"error": str(exc)})
                return self._send(201, {"id": service.start_run(config)})
            if path == "/accounts":
                try:
                    account = Account.model_validate(self._body())
                except Exception as exc:  # noqa: BLE001
                    return self._send(400, {"error": str(exc)})
                service.accounts.add(account)
                return self._send(201, account.masked())
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
                try:
                    return self._send(200, oauth.start(self._body().get("provider", "")))
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
            return self._send(404, {"error": "not found"})

        # ── PATCH ──
        def do_PATCH(self) -> None:  # noqa: N802 - http.server API
            path = _strip_api_prefix(urlparse(self.path).path)
            if path.startswith("/accounts/"):
                acct = service.accounts.update(path.removeprefix("/accounts/"), self._body())
                if not acct:
                    return self._send(404, {"error": "unknown account"})
                return self._send(200, acct.masked())
            return self._send(404, {"error": "not found"})

        # ── DELETE ──
        def do_DELETE(self) -> None:  # noqa: N802 - http.server API
            path = _strip_api_prefix(urlparse(self.path).path)
            if path.startswith("/accounts/"):
                ok = service.accounts.remove(path.removeprefix("/accounts/"))
                if not ok:
                    return self._send(404, {"error": "unknown account"})
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})

        # ── GET ──
        def do_GET(self) -> None:  # noqa: N802 - http.server API
            parsed = urlparse(self.path)
            path = _strip_api_prefix(parsed.path)
            if path == "/provider-types":
                return self._send(200, PROVIDER_TYPES)
            if path == "/oauth/providers":
                return self._send(200, {
                    pid: {"flow": p.flow, "supported": p.supported,
                          "reason": p.unsupported_reason}
                    for pid, p in OAUTH_PROVIDERS.items()
                })
            if path == "/accounts":
                return self._send(200, _router_view(service))
            if path.startswith("/accounts/") and path.endswith("/models"):
                aid = path[len("/accounts/") : -len("/models")]
                acct = service.accounts.get(aid)
                if not acct:
                    return self._send(404, {"error": "unknown account"})
                return self._send(200, {"models": probe_models(acct.base_url, acct.api_key)})
            if path == "/memory":
                target = (parse_qs(parsed.query).get("target") or [""])[0]
                return self._send(200, service.memory_summary(target))
            # ── pillars (knowledge base / vuln search / labs / i18n) ──
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
            if path == "/labs":
                return self._send(200, service.pillars.labs_list())
            if path.startswith("/i18n/"):
                return self._send(200, service.pillars.i18n(path.removeprefix("/i18n/")))
            if path == "/runs":
                return self._send(200, {"runs": service.list_runs()})
            if path == "/findings":
                target = (query.get("target") or [""])[0]
                return self._send(200, service.findings_summary(target))
            if path.startswith("/runs/") and path.endswith("/report"):
                rid = path[len("/runs/") : -len("/report")]
                fmt = (query.get("format") or ["md"])[0]
                report = service.run_report(rid, fmt)
                if report is None:
                    return self._send(404, {"error": "unknown run id"})
                payload = report if fmt == "json" else {"format": "md", "report": report}
                return self._send(200, payload)
            if path.startswith("/runs/"):
                run = service.get_run(path.removeprefix("/runs/"))
                if not run:
                    return self._send(404, {"error": "unknown run id"})
                return self._send(200, run.model_dump_json())
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
    return ThreadingHTTPServer((host, port), make_handler(service, static_root))


def main() -> None:
    host = os.getenv("SECFORGE_API_HOST", DEFAULT_HOST)
    port = int(os.getenv("SECFORGE_API_PORT", str(DEFAULT_PORT)))
    server = build_server(RunService(), host, port)
    print(f"SecForge API on http://{host}:{port}  (runs, /accounts router, /memory)")
    server.serve_forever()


if __name__ == "__main__":
    main()
