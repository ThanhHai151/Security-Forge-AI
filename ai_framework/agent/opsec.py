"""OPSEC pacing — make the stealth the system prompt preaches actually happen.

The agent is told to "blend with legitimate traffic" and that "a perfectly regular beacon is
an attribution handle". Without pacing that is just prose: the loop fires network tools as
fast as the model emits them. ``Pacer`` enforces a minimum gap between network actions to the
same host, plus random jitter so the cadence is *not* perfectly regular.

Pure and injectable: the clock, sleeper, and RNG are all parameters, so tests run instantly
and deterministically. A zero ``min_interval`` (the default) is a no-op — pacing is opt-in via
``RunConfig.opsec_min_interval`` / ``opsec_jitter``.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable


class Pacer:
    def __init__(
        self,
        min_interval: float = 0.0,
        jitter: float = 0.0,
        *,
        seed: int | None = None,
        time_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.min_interval = max(0.0, min_interval)
        self.jitter = max(0.0, jitter)
        self._time = time_fn
        self._sleep = sleep_fn
        self._rng = random.Random(seed)
        self._last: dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        return self.min_interval > 0 or self.jitter > 0

    def wait(self, host: str) -> float:
        """Sleep as needed before touching ``host`` again; return seconds actually slept."""
        if not self.enabled:
            return 0.0
        now = self._time()
        last = self._last.get(host)
        target_gap = self.min_interval + (self._rng.random() * self.jitter if self.jitter else 0.0)
        delay = 0.0
        if last is not None:
            delay = max(0.0, target_gap - (now - last))
        if delay > 0:
            self._sleep(delay)
        self._last[host] = self._time()
        return delay
