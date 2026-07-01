"""``secforge`` — the single entrypoint the installers put on your PATH.

Run ``secforge`` with no arguments for an interactive menu:

    SecForge
      1) Web UI         - start the server and open it in your browser
      2) Terminal UI    - interactive CLI, no browser
      3) Serve only     - start the server, don't open anything (Ctrl-C to stop)
      q) Quit

Both UIs are backed by one unified server (Web UI + ``/api`` on a single port, 61022).
Non-interactive subcommands for scripts/CI:

    secforge web        # serve + open browser
    secforge tui        # Terminal UI
    secforge serve      # serve only (foreground)
    secforge --help

Host/port override via SECFORGE_API_HOST / SECFORGE_API_PORT.
"""

from __future__ import annotations

import os
import sys
import threading
import webbrowser
from pathlib import Path

from backend.app import build_server
from backend.service import RunService

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 61022  # unified Web UI + API. (Dev mode uses 61020/61021; see backend/app.py.)


def _repo_root() -> Path:
    # backend/launcher.py -> repo root is one level up from the package dir.
    return Path(__file__).resolve().parent.parent


def _frontend_dist() -> Path | None:
    """The built frontend, if present. ``None`` (with a hint) when not yet built."""
    dist = _repo_root() / "frontend" / "dist"
    return dist if (dist / "index.html").is_file() else None


def _host_port() -> tuple[str, int]:
    host = os.getenv("SECFORGE_API_HOST", DEFAULT_HOST)
    port = int(os.getenv("SECFORGE_API_PORT", str(DEFAULT_PORT)))
    return host, port


def _start_server(open_browser: bool) -> None:
    host, port = _host_port()
    dist = _frontend_dist()
    service = RunService()
    server = build_server(service, host, port, static_root=dist)
    url = f"http://{host}:{port}"

    if dist is None:
        print("[!] Web UI not built yet - serving API only.")
        print("    Build it with:  cd frontend && npm install && npm run build")
        print(f"    API is live at: {url}/api")
    else:
        print(f"SecForge is running at {url}")

    if open_browser and dist is not None:
        # Open the browser shortly after the server starts accepting connections.
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SecForge…")
        server.shutdown()


def _run_tui() -> None:
    from backend.tui import run_tui

    run_tui()


def _menu() -> None:
    print("\n  SecForge")
    print("  --------")
    print("  1) Web UI       - start the server and open it in your browser")
    print("  2) Terminal UI  - interactive CLI, no browser")
    print("  3) Serve only   - start the server, don't open a browser")
    print("  q) Quit\n")
    try:
        choice = input("  Select [1]: ").strip().lower() or "1"
    except EOFError:
        choice = "1"
    if choice in ("1", "web"):
        _start_server(open_browser=True)
    elif choice in ("2", "tui", "terminal"):
        _run_tui()
    elif choice in ("3", "serve"):
        _start_server(open_browser=False)
    elif choice in ("q", "quit", "exit"):
        return
    else:
        print(f"  Unknown choice: {choice!r}")


HELP = __doc__


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    cmd = args[0].lower() if args else ""

    if cmd in ("-h", "--help", "help"):
        print(HELP)
        return
    if cmd == "web":
        return _start_server(open_browser=True)
    if cmd in ("tui", "terminal"):
        return _run_tui()
    if cmd == "serve":
        return _start_server(open_browser=False)
    if cmd:
        print(f"Unknown command: {cmd!r}\n")
        print(HELP)
        return

    try:
        _menu()
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
