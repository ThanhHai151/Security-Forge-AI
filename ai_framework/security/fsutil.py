"""Filesystem hardening helpers for the durable stores.

Runtime stores (runs, campaigns, findings, memory, assets, evidence) can hold credentials,
target data, prompts, and evidence. They must not be world/group-readable, so every writer
restricts the file to owner-only (``0600``) — the default umask commonly leaves them ``0644``.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

_OWNER_ONLY = 0o600


def restrict(path: str | Path) -> None:
    """Best-effort ``chmod 0600`` on a store file (no-op on filesystems without POSIX perms)."""
    try:
        os.chmod(path, _OWNER_ONLY)
    except OSError:
        pass


def open_private_append(path: str | Path) -> io.TextIOWrapper:
    """Open ``path`` for text append, creating it owner-only (0600) *at creation time*.

    Using ``os.open`` with the mode closes the window a plain ``open("a")`` leaves — where the
    file briefly exists at the umask default (often 0644) before a post-hoc chmod — during which a
    local user could open it and retain a readable descriptor. ``restrict`` is still called so a
    pre-existing looser file is tightened too.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, _OWNER_ONLY)
    restrict(path)
    return os.fdopen(fd, "a", encoding="utf-8")


def write_private_text(path: str | Path, text: str) -> None:
    """Write ``text`` to ``path`` (truncating) with owner-only perms from creation."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _OWNER_ONLY)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    restrict(path)
