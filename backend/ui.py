"""Neon terminal UI — arrow-key menus and styling that mirror the Web UI.

A dependency-free toolkit shared by ``backend.launcher`` and ``backend.tui``. The
palette is lifted straight from ``frontend/src/index.css`` (the LyteNyte navy-ink +
neon-teal look) so the terminal and the browser feel like one product:

    teal accent   #22B890   bright #40D4A8   glow #6EE8C2
    navy ink      #0C1220 → #1C2438          text #D8E4F8   muted #5870A0

``select()`` renders an interactive list you drive with ↑/↓ (or j/k), Enter to
choose, number keys as shortcuts, and q/Esc to cancel. On a non-interactive stdin
(pipes, CI) it degrades to a plain numbered prompt, so scripts keep working.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# ── 24-bit truecolor, matched to frontend/src/index.css ──────────────────────
_TEAL = "\x1b[38;2;34;184;144m"       # #22B890  accent
_TEAL_HI = "\x1b[38;2;64;212;168m"    # #40D4A8  bright accent
_TEAL_GLOW = "\x1b[38;2;110;232;194m"  # #6EE8C2  glow / hover text
_TEXT = "\x1b[38;2;216;228;248m"      # #D8E4F8  primary text
_MUTED = "\x1b[38;2;88;112;160m"      # #5870A0  muted / secondary
_DIM = "\x1b[38;2;60;80;112m"         # #3C5070  dimmest
_AMBER = "\x1b[38;2;245;181;71m"      # #F5B547  status amber
_SEL_BG = "\x1b[48;2;18;30;40m"       # subtle teal-tinted row background

_BOLD = "\x1b[1m"
_RESET = "\x1b[0m"
_HIDE_CURSOR = "\x1b[?25l"
_SHOW_CURSOR = "\x1b[?25h"

_POINTER = "▸"  # ▸  neon selection arrow (mirrors the web nav-row accent bar)


@dataclass(frozen=True)
class Choice:
    """One selectable row: ``key`` is the shortcut/return value, plus display text."""

    key: str
    label: str
    hint: str = ""


def _enable_ansi() -> bool:
    """Turn on ANSI/VT processing. Returns whether colour output is worthwhile."""
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes

            # ``getattr`` (not ``ctypes.windll.kernel32``) keeps this untyped on every
            # platform — ``windll`` only exists in typeshed under win32, so a direct
            # attribute access would trip mypy's warn_unused_ignores off-Windows.
            windll = getattr(ctypes, "windll", None)
            if windll is None:
                return False
            kernel32 = windll.kernel32
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004 on the output handle (-11).
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:  # noqa: BLE001 — fall back to plain text if VT can't be set
            return False
    return True


_COLOR = _enable_ansi()


def _c(code: str, text: str) -> str:
    """Wrap ``text`` in an ANSI colour if colour output is enabled."""
    return f"{code}{text}{_RESET}" if _COLOR else text


def banner(title: str = "SecForge", subtitle: str = "") -> None:
    """Print the neon SecForge header — a teal-glow wordmark over a rule."""
    if not _COLOR:
        print(f"\n  {title}")
        print("  " + "-" * len(title))
        if subtitle:
            print(f"  {subtitle}")
        print()
        return

    spaced = " ".join(title.upper())
    rule = "─" * (len(spaced) + 6)
    print()
    print("  " + _c(_TEAL, "▄" * (len(spaced) + 6)))  # ▄ glow shelf on top
    print("  " + _c(_BOLD + _TEAL_GLOW, f"  {spaced}  "))
    print("  " + _c(_TEAL, rule))
    if subtitle:
        print("  " + _c(_MUTED, subtitle))
    print()


def _render(title: str, choices: list[Choice], active: int) -> None:
    if title:
        print("  " + _c(_MUTED, title))
        print()
    for i, ch in enumerate(choices):
        selected = i == active
        pointer = _c(_TEAL_HI + _BOLD, _POINTER) if selected else " "
        key = _c(_TEAL_HI if selected else _MUTED, ch.key)
        if selected:
            label = _c(_SEL_BG + _TEAL_GLOW + _BOLD, f" {ch.label} ")
            hint = _c(_SEL_BG + _MUTED, f"{ch.hint} ") if ch.hint else ""
            print(f"  {pointer} {key}  {label}{hint}")
        else:
            label = _c(_TEXT, ch.label)
            hint = _c(_DIM, ch.hint) if ch.hint else ""
            gap = " " * max(1, 14 - len(ch.label))
            print(f"  {pointer} {key}  {label}{gap}{hint}")
    print()
    print("  " + _c(_DIM, "↑/↓ move · enter select · q quit"))


def _clear(lines: int) -> None:
    # Move up ``lines`` and clear each, so the menu redraws in place.
    sys.stdout.write(f"\x1b[{lines}A")
    sys.stdout.write("\x1b[J")
    sys.stdout.flush()


def _read_key() -> str:
    """Block for one keypress, returning a normalized token.

    Tokens: ``up``/``down``/``enter``/``esc``, or the literal character typed.
    Handles Windows (msvcrt) and POSIX (termios) arrow-key escape sequences.
    """
    # ``sys.platform`` (not ``os.name``) so mypy narrows the platform-specific
    # branches — termios/tty exist only off-Windows, msvcrt only on Windows.
    if sys.platform == "win32":
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):  # arrow/function keys arrive as a 2-char pair
            code = msvcrt.getwch()
            return {"H": "up", "P": "down"}.get(code, "")
        if ch in ("\r", "\n"):
            return "enter"
        if ch == "\x1b":
            return "esc"
        if ch == "\x03":  # Ctrl-C
            raise KeyboardInterrupt
        return ch
    else:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":  # CSI escape sequence: ESC [ A/B
                seq = sys.stdin.read(2)
                return {"[A": "up", "[B": "down"}.get(seq, "esc")
            if ch in ("\r", "\n"):
                return "enter"
            if ch == "\x03":
                raise KeyboardInterrupt
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _select_plain(title: str, choices: list[Choice], default: str) -> str | None:
    """Numbered-prompt fallback for non-interactive stdin (pipes, CI, redirects)."""
    if title:
        print("  " + title + "\n")
    for ch in choices:
        hint = f" - {ch.hint}" if ch.hint else ""
        print(f"  {ch.key}) {ch.label}{hint}")
    print()
    try:
        raw = input(f"  Select [{default}]: ").strip().lower() or default
    except EOFError:
        return default
    for ch in choices:
        if raw == ch.key.lower() or raw == ch.label.lower():
            return ch.key
    return raw or None


def select(
    choices: list[Choice],
    *,
    title: str = "",
    default: str | None = None,
) -> str | None:
    """Show an arrow-key menu; return the chosen ``Choice.key`` (or ``None`` on cancel).

    Falls back to a plain numbered prompt when stdin is not a TTY.
    """
    default_key = default or choices[0].key
    if not (_COLOR and sys.stdin.isatty()):
        return _select_plain(title, choices, default_key)

    active = next((i for i, c in enumerate(choices) if c.key == default_key), 0)
    # Rendered height: optional (title + blank), one line per choice, blank, footer.
    height = len(choices) + 2 + (2 if title else 0)

    sys.stdout.write(_HIDE_CURSOR)
    try:
        _render(title, choices, active)
        while True:
            key = _read_key()
            if key in ("up", "k"):
                active = (active - 1) % len(choices)
            elif key in ("down", "j"):
                active = (active + 1) % len(choices)
            elif key == "enter":
                return choices[active].key
            elif key in ("q", "esc"):
                return None
            else:
                match = next((c for c in choices if c.key.lower() == key.lower()), None)
                if match is not None:
                    return match.key
                continue  # ignore unmapped keys without redrawing
            _clear(height)
            _render(title, choices, active)
    finally:
        sys.stdout.write(_SHOW_CURSOR)
        sys.stdout.flush()
