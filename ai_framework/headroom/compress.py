"""Headroom compression — squeeze tokens out of inputs and organize stored memory.

Two jobs:

* ``compress_log`` — shrink a tool/output log *losslessly first* (collapse repeated lines and
  trailing whitespace — pentest logs are full of repetition), and only head/tail-truncate if it
  is still over budget. Strictly better than blind truncation: it keeps more signal per token.
* ``consolidate_memory`` — keep the Hermes store organized so it grows without bloating context:
  drop exact duplicates, and when one (target, technique) has many ``attempt`` records, keep the
  most recent few and fold the rest into a single counted ``lesson`` line.

Both are pure functions over the contracts so they are trivial to test and reuse.
"""

from __future__ import annotations

import re
from collections import defaultdict

from ai_framework.agent.contracts import MemoryKind, MemoryRecord
from ai_framework.headroom.budget import count_tokens

_WS = re.compile(r"[ \t]+")


def _collapse_repeats(text: str) -> str:
    """Collapse consecutive identical lines into one with an ``(xN)`` marker; trim trailing ws."""
    out: list[str] = []
    prev: str | None = None
    run = 0
    for raw in text.splitlines():
        line = _WS.sub(" ", raw.rstrip())
        if line == prev:
            run += 1
            continue
        if prev is not None and run > 1:
            out[-1] = f"{prev}  (x{run})"
        out.append(line)
        prev = line
        run = 1
    if prev is not None and run > 1:
        out[-1] = f"{prev}  (x{run})"
    return "\n".join(out)


def compress_log(log: str, max_tokens: int) -> tuple[str, int]:
    """Return (compressed_log, tokens_saved). Lossless collapse first, then head/tail truncate."""
    before = count_tokens(log)
    if before <= max_tokens:
        return log, 0
    collapsed = _collapse_repeats(log)
    if count_tokens(collapsed) <= max_tokens:
        return collapsed, max(0, before - count_tokens(collapsed))
    # Still too big: keep a head+tail window (~max_tokens), measured in chars (4 chars/token).
    keep_chars = max(8, max_tokens * 4)
    half = keep_chars // 2
    dropped = max(0, len(collapsed) - 2 * half)
    new = f"{collapsed[:half]}\n[...compressed {dropped} chars...]\n{collapsed[-half:]}"
    return new, max(0, before - count_tokens(new))


def _key(r: MemoryRecord) -> tuple[str, str, str, str]:
    return (str(r.kind), r.target, r.technique, r.body)


def consolidate_memory(
    records: list[MemoryRecord], keep_attempts_per_group: int = 3
) -> list[MemoryRecord]:
    """Dedupe identical records and fold noisy attempt-spam into one counted lesson per group.

    Order is otherwise preserved (newest-first inputs stay newest-first). This keeps the store
    organized: facts/lessons survive intact; long runs of dead-end attempts compress to a tally.
    """
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[MemoryRecord] = []
    for r in records:
        k = _key(r)
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)

    # Fold surplus attempts per (target, technique) into a single counted lesson.
    attempts: dict[tuple[str, str], list[MemoryRecord]] = defaultdict(list)
    for r in deduped:
        if r.kind == MemoryKind.attempt:
            attempts[(r.target, r.technique)].append(r)

    surplus_ids: set[str] = set()
    extra: list[MemoryRecord] = []
    for (target, technique), group in attempts.items():
        if len(group) <= keep_attempts_per_group:
            continue
        old = group[keep_attempts_per_group:]
        surplus_ids.update(r.id for r in old)
        extra.append(
            MemoryRecord(
                id=f"lesson:{target}:{technique}",
                kind=MemoryKind.lesson,
                target=target,
                technique=technique,
                body=f"{len(old)} further dead-end attempts on {technique} (folded by Headroom).",
            )
        )

    result = [r for r in deduped if r.id not in surplus_ids]
    result.extend(extra)
    return result
