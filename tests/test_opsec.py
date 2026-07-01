"""OPSEC pacer: enforce a minimum gap (+ jitter) between network actions, deterministically."""

from ai_framework.agent.opsec import Pacer


class _Clock:
    """A fake monotonic clock whose sleeper advances time, so tests need no real waiting."""

    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.t

    def sleep(self, secs: float) -> None:
        self.sleeps.append(secs)
        self.t += secs


def test_disabled_pacer_never_sleeps():
    clock = _Clock()
    pacer = Pacer(0.0, 0.0, time_fn=clock.time, sleep_fn=clock.sleep)
    assert not pacer.enabled
    assert pacer.wait("host") == 0.0
    assert clock.sleeps == []


def test_first_action_is_immediate_then_gap_is_enforced():
    clock = _Clock()
    pacer = Pacer(min_interval=10.0, jitter=0.0, time_fn=clock.time, sleep_fn=clock.sleep)
    assert pacer.wait("host") == 0.0        # nothing to wait for on the first hit
    clock.t = 3.0                            # 3s of "work" happens
    slept = pacer.wait("host")               # only 7s left to reach the 10s gap
    assert slept == 7.0
    assert clock.sleeps == [7.0]


def test_gap_is_per_host():
    clock = _Clock()
    pacer = Pacer(min_interval=10.0, jitter=0.0, time_fn=clock.time, sleep_fn=clock.sleep)
    pacer.wait("a")
    assert pacer.wait("b") == 0.0            # a different host has its own timer
    assert clock.sleeps == []


def test_jitter_is_seeded_and_bounded():
    clock = _Clock()
    pacer = Pacer(min_interval=0.0, jitter=5.0, seed=1, time_fn=clock.time, sleep_fn=clock.sleep)
    assert pacer.enabled
    pacer.wait("h")                          # primes the timer
    slept = pacer.wait("h")
    assert 0.0 <= slept <= 5.0
