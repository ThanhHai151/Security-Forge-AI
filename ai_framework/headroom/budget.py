"""Token accounting for Headroom.

Offline backend uses a fast char/word heuristic (§3.1, Open question §6); a Claude backend
can swap in exact counting later. ``count_tokens`` is the single entry point everything
else calls so the estimator can be replaced in one place.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ai_framework.agent.contracts import MemoryRecord, Turn

# Rough bytes-per-token for English+JSON. Deliberately conservative so we compact a little
# early rather than overflow. The default when no exact tokenizer is installed.
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """Heuristic token count for a string. Never returns < 1 for non-empty text."""
    if not text:
        return 0
    return max(1, (len(text) + _CHARS_PER_TOKEN - 1) // _CHARS_PER_TOKEN)


# The active counter. Everything in Headroom counts through ``count_tokens`` so an exact
# tokenizer can be installed in exactly one place (INTEGRATION_PLAN §6 open question).
_counter: Callable[[str], int] = estimate_tokens


def set_token_counter(fn: Callable[[str], int]) -> None:
    """Install the token counter Headroom uses (e.g. an exact tokenizer for a backend)."""
    global _counter
    _counter = fn


def reset_token_counter() -> None:
    """Restore the default heuristic counter."""
    global _counter
    _counter = estimate_tokens


def count_tokens(text: str) -> int:
    """Count tokens with the active counter (heuristic unless one was installed)."""
    return _counter(text)


def tiktoken_counter(encoding_name: str = "cl100k_base") -> Callable[[str], int]:
    """A local, exact-per-encoding counter backed by ``tiktoken`` (lazy import).

    Note: ``cl100k_base`` is not Claude's tokenizer, but it is a far closer local proxy
    than chars/4 and needs no network. For ground-truth Claude counts use the Anthropic
    ``messages.count_tokens`` API on the assembled request.
    """
    import tiktoken  # imported lazily so the offline path never needs the dependency

    enc = tiktoken.get_encoding(encoding_name)

    def count(text: str) -> int:
        return len(enc.encode(text)) if text else 0

    return count


def turn_tokens(turn: Turn) -> int:
    """Tokens a single turn contributes: reasoning + tool calls + logs + next plan."""
    total = count_tokens(turn.reasoning) + count_tokens(turn.next_plan)
    for call in turn.tool_calls:
        total += count_tokens(call.name) + count_tokens(json.dumps(call.arguments))
    for result in turn.tool_results:
        total += count_tokens(result.log)
    return total


def tools_tokens(tools: list[dict[str, Any]]) -> int:
    return count_tokens(json.dumps(tools))


def memory_tokens(memory: list[MemoryRecord]) -> int:
    return sum(count_tokens(r.body) + count_tokens(r.technique) for r in memory)
