"""Dependency-free dev auto-reloader — the backend's answer to Vite's HMR.

``backend/app.py`` is a plain ``ThreadingHTTPServer`` with no reload support: every edit to
``backend/`` or ``ai_framework/`` needs a manual Ctrl-C + rerun today. This module polls file
mtimes under those two directories and restarts the target process the moment one changes, so
editing backend code feels as instant as editing frontend code under Vite.

Polling (not a filesystem-events library like ``watchdog``) keeps this dependency-free — a
handful of source directories is cheap enough to stat every tick, and this project otherwise
ships with no extra runtime dependencies.

Usage::

    python -m backend.devreload                    # restarts `python -u -m backend.app`
    python -m backend.devreload backend.launcher serve   # restarts any module + args
"""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
# Only server code lives here; touching tests/docs shouldn't bounce a running server.
_WATCH_DIRS = (_REPO_ROOT / "backend", _REPO_ROOT / "ai_framework")
_POLL_SECONDS = 0.75
_DEBOUNCE_SECONDS = 0.3

Spawn = Callable[[list[str]], "subprocess.Popen[bytes]"]


def snapshot(watch_dirs: tuple[Path, ...] = _WATCH_DIRS) -> dict[str, float]:
    """``{path: mtime}`` for every ``.py`` file under ``watch_dirs`` (skips ``__pycache__``)."""
    files: dict[str, float] = {}
    for root in watch_dirs:
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            try:
                files[str(path)] = path.stat().st_mtime
            except OSError:
                continue  # removed mid-scan; the next snapshot settles
    return files


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def run(
    argv: list[str],
    *,
    watch_dirs: tuple[Path, ...] = _WATCH_DIRS,
    spawn: Spawn = subprocess.Popen,
    sleep: Callable[[float], None] = time.sleep,
    poll_seconds: float = _POLL_SECONDS,
    debounce_seconds: float = _DEBOUNCE_SECONDS,
) -> None:
    """Spawn ``python -u -m <argv>`` and restart it whenever a watched ``.py`` file changes.

    Runs until Ctrl-C or the child process exits on its own (crash, or something inside it
    called ``sys.exit``). ``spawn``/``sleep`` are injectable so tests never launch a real
    subprocess or wait on a real clock.
    """
    cmd = [sys.executable, "-u", "-m", *argv]
    proc = spawn(cmd)
    last = snapshot(watch_dirs)
    print(
        f"[devreload] watching {', '.join(d.name for d in watch_dirs)} for changes "
        "(Ctrl-C to stop)"
    )
    try:
        while True:
            sleep(poll_seconds)
            if proc.poll() is not None:
                print(f"[devreload] server exited ({proc.returncode}); stopping")
                return
            current = snapshot(watch_dirs)
            if current == last:
                continue
            sleep(debounce_seconds)  # let a burst of saves (editor "save all") settle
            last = snapshot(watch_dirs)
            print("[devreload] change detected — restarting server")
            _terminate(proc)
            proc = spawn(cmd)
    except KeyboardInterrupt:
        print("\n[devreload] stopping")
    finally:
        _terminate(proc)


def main() -> None:
    run(sys.argv[1:] or ["backend.app"])


if __name__ == "__main__":
    main()
