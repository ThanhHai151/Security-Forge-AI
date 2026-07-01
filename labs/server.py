"""The labs HTTP server — localhost-only, separate port, **disabled by default**.

Containment (``labs/README.md`` › Safety posture): the deliberately-vulnerable code never
runs inside the main console. It binds ``127.0.0.1`` only, on its own port, and refuses to
start unless explicitly enabled (``enabled=True`` or ``SECFORGE_LABS_ENABLED=1``).

Routes (under ``/labs``):
    GET  /labs                      -> JSON list of labs (+ solved state)
    GET|POST /labs/<slug>[/path]    -> the lab's own response (text/html)
    POST /labs/<slug>/reset         -> reset that lab to a clean, unsolved state
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from labs.base import LabRequest
from labs.registry import LabRegistry, default_registry

LABS_HOST = "127.0.0.1"  # never anything else — these targets are intentionally vulnerable
DEFAULT_LABS_PORT = 61023


def labs_enabled(flag: bool | None = None) -> bool:
    """Resolve the opt-in: explicit ``flag`` wins, else the env var, else False."""
    if flag is not None:
        return flag
    return os.getenv("SECFORGE_LABS_ENABLED", "").lower() in {"1", "true", "yes", "on"}


def _flatten(qs: dict[str, list[str]]) -> dict[str, str]:
    return {k: v[0] for k, v in qs.items() if v}


def make_labs_handler(registry: LabRegistry) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: str, ctype: str = "application/json") -> None:
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _dispatch(self, method: str) -> None:
            parsed = urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            if parts == ["labs"]:
                return self._send(200, json.dumps([m.model_dump() for m in registry.list()]))
            if len(parts) >= 2 and parts[0] == "labs":
                slug = parts[1]
                rest = "/" + "/".join(parts[2:])
                if rest.rstrip("/") == "/reset" and method == "POST":
                    ok = registry.reset(slug)
                    return self._send(200 if ok else 404, json.dumps({"reset": ok}))
                body = {}
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length:
                    raw = self.rfile.read(length).decode("utf-8", "replace")
                    body = _flatten(parse_qs(raw))
                req = LabRequest(
                    method=method,
                    path=rest,
                    query=_flatten(parse_qs(parsed.query)),
                    body=body,
                )
                resp = registry.handle(slug, req)
                # Surface solved-state in a header so the console can react without parsing HTML.
                data = resp.body.encode("utf-8")
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.content_type)
                self.send_header("X-Lab-Solved", "1" if resp.solved else "0")
                # Header values must be latin-1; keep the note ASCII-safe (em dashes etc.).
                self.send_header("X-Lab-Note", resp.note.encode("ascii", "replace").decode("ascii"))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            return self._send(404, json.dumps({"error": "not found"}))

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            self._dispatch("POST")

        def log_message(self, *args: object) -> None:
            pass

    return Handler


def build_labs_server(
    registry: LabRegistry | None = None,
    port: int = DEFAULT_LABS_PORT,
    enabled: bool | None = None,
) -> ThreadingHTTPServer:
    """Construct (but don't start) the labs server. Raises unless explicitly enabled."""
    if not labs_enabled(enabled):
        raise RuntimeError(
            "labs are disabled by default; enable with SECFORGE_LABS_ENABLED=1 "
            "or build_labs_server(enabled=True)"
        )
    registry = registry or default_registry()
    return ThreadingHTTPServer((LABS_HOST, port), make_labs_handler(registry))


def main() -> None:
    port = int(os.getenv("SECFORGE_LABS_PORT", str(DEFAULT_LABS_PORT)))
    server = build_labs_server(port=port, enabled=labs_enabled())
    print(f"SecForge labs (sandboxed, vulnerable) on http://{LABS_HOST}:{port}/labs")
    server.serve_forever()


if __name__ == "__main__":
    main()
