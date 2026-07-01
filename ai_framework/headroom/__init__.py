"""Headroom — context-window budgeting & compaction.

Sits between the agent loop and the model backend (INTEGRATION_PLAN.md §3): it measures
how many tokens the assembled request needs and, when that would eat into the reserved
output headroom, compacts the request along a fixed priority ladder — never silently,
always producing a ``CompactionReport``. It does not reason; it measures and shapes.
"""

from __future__ import annotations

from ai_framework.headroom.budget import (
    count_tokens,
    estimate_tokens,
    reset_token_counter,
    set_token_counter,
    tiktoken_counter,
)
from ai_framework.headroom.fit import FittedRequest, TurnRequest, fit

__all__ = [
    "FittedRequest",
    "TurnRequest",
    "count_tokens",
    "estimate_tokens",
    "fit",
    "reset_token_counter",
    "set_token_counter",
    "tiktoken_counter",
]
