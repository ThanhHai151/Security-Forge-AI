"""Dev auto-reloader: mtime snapshotting + restart-on-change.

``spawn``/``sleep`` are injected so this never launches a real subprocess or waits on a real
clock — the fake process and fake clock drive the loop deterministically.
"""

import os

from backend import devreload


class _FakeProc:
    """Stand-in for ``subprocess.Popen`` — tracks whether it was terminated."""

    def __init__(self):
        self.terminate_calls = 0
        self._exited = False
        self.returncode = None

    def poll(self):
        return self.returncode if self._exited else None

    def terminate(self):
        self.terminate_calls += 1
        self._exited = True
        self.returncode = -15

    def wait(self, timeout=None):
        return 0


def test_snapshot_ignores_pycache_and_tracks_py_files(tmp_path):
    watched = tmp_path / "pkg"
    watched.mkdir()
    (watched / "a.py").write_text("x = 1")
    before = devreload.snapshot((watched,))
    assert set(before) == {str(watched / "a.py")}

    cache = watched / "__pycache__"
    cache.mkdir()
    (cache / "a.cpython-311.pyc").write_text("junk")
    (cache / "ignored.py").write_text("junk")  # even a .py under __pycache__ is skipped

    after = devreload.snapshot((watched,))
    assert set(after) == set(before)


def test_run_restarts_the_process_when_a_watched_file_changes(tmp_path):
    watched = tmp_path / "pkg"
    watched.mkdir()
    target = watched / "mod.py"
    target.write_text("x = 1")

    procs: list[_FakeProc] = []

    def fake_spawn(cmd):
        proc = _FakeProc()
        procs.append(proc)
        return proc

    calls = {"n": 0}

    def fake_sleep(_seconds):
        calls["n"] += 1
        if calls["n"] == 1:
            # Simulate an edit landing while the reloader is on its first poll wait.
            bumped = target.stat().st_mtime + 5
            os.utime(target, (bumped, bumped))
        elif calls["n"] >= 4:
            raise KeyboardInterrupt

    devreload.run(
        ["some.module"],
        watch_dirs=(watched,),
        spawn=fake_spawn,
        sleep=fake_sleep,
        poll_seconds=0,
        debounce_seconds=0,
    )

    assert len(procs) == 2  # initial spawn + exactly one restart
    assert procs[0].terminate_calls == 1  # torn down when the change was detected
    assert procs[1].terminate_calls == 1  # torn down on the final Ctrl-C cleanup


def test_run_stops_without_restarting_when_nothing_changes(tmp_path):
    watched = tmp_path / "pkg"
    watched.mkdir()
    (watched / "mod.py").write_text("x = 1")

    procs: list[_FakeProc] = []

    def fake_spawn(cmd):
        proc = _FakeProc()
        procs.append(proc)
        return proc

    calls = {"n": 0}

    def fake_sleep(_seconds):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise KeyboardInterrupt

    devreload.run(
        ["some.module"],
        watch_dirs=(watched,),
        spawn=fake_spawn,
        sleep=fake_sleep,
        poll_seconds=0,
        debounce_seconds=0,
    )

    assert len(procs) == 1  # no restart triggered
    assert procs[0].terminate_calls == 1  # still cleaned up on exit


def test_run_stops_when_the_child_process_exits_on_its_own(tmp_path):
    watched = tmp_path / "pkg"
    watched.mkdir()

    proc = _FakeProc()
    proc._exited = True  # crashed before the first poll
    proc.returncode = 1

    devreload.run(
        ["some.module"],
        watch_dirs=(watched,),
        spawn=lambda cmd: proc,
        sleep=lambda _s: None,
        poll_seconds=0,
        debounce_seconds=0,
    )

    # already-exited process: _terminate() is a no-op (poll() is not None)
    assert proc.terminate_calls == 0
