"""05.1-gap — per-collector wall-clock self-bounding regression tests.

Blocker A root cause: the between-collector deadline in ``run_collectors``
(D-051-06) could not interrupt a single collector once it had started. The
secret_detection collector spawns a gitleaks subprocess PER text file, so on the
40 GB adapt monorepo it ran far past the scan budget. The fix threads the SHARED
scan deadline (a ``time.perf_counter`` value) INTO the read-heavy / subprocess
collectors; each polls it from inside its own loop and self-reports
``status='timeout'`` (-> partial banner + scope-ledger disclosure, SAFE-08)
rather than running unbounded.

These tests pin:
  1. ``run_collectors`` threads ``deadline`` into collectors that declare it and
     does NOT pass it to plain ``(repo_path, repo_index)`` collectors / test
     doubles (signature-inspection contract).
  2. An already-expired deadline makes each self-bounding collector stop early
     and report ``status='timeout'`` with an honest notes string — coverage is
     bounded but disclosed, never silently dropped.
  3. ``deadline=None`` preserves the prior full-sweep behaviour.
  4. ``DeadlineGuard`` first-tick + interval polling and ``remaining_seconds``
     boundaries behave as documented.
"""
from __future__ import annotations

import time

from repo_audit.collectors import _accepts_deadline, run_collectors
from repo_audit.collectors._budget import DeadlineGuard, remaining_seconds
from repo_audit.collectors.base import CollectorResult
from repo_audit.walker import build_repo_index


# --- 1. signature-inspection threading contract ----------------------------


def test_accepts_deadline_detects_keyword():
    def with_deadline(repo_path, repo_index, *, deadline=None):  # noqa: ARG001
        return CollectorResult(status="ok")

    def without_deadline(repo_path, repo_index):  # noqa: ARG001
        return CollectorResult(status="ok")

    assert _accepts_deadline(with_deadline) is True
    assert _accepts_deadline(without_deadline) is False


def test_run_collectors_threads_deadline_only_to_optin(monkeypatch):
    """run_collectors passes deadline= to opt-in collectors, omits it otherwise."""
    import repo_audit.collectors as coll

    seen: dict[str, object] = {}

    def optin(repo_path, repo_index, *, deadline=None):  # noqa: ARG001
        seen["optin"] = deadline
        return CollectorResult(status="ok", source_collector="optin")

    def plain(repo_path, repo_index):  # noqa: ARG001
        seen["plain"] = "called"
        return CollectorResult(status="ok", source_collector="plain")

    monkeypatch.setattr(coll, "_REGISTRY", [optin, plain])
    dl = time.perf_counter() + 1000.0
    results = run_collectors("/nonexistent", {}, deadline=dl)
    assert seen["optin"] == dl          # opt-in collector received the deadline
    assert seen["plain"] == "called"    # plain collector still ran (no kwarg)
    assert len(results) == 2


# --- 2. expired deadline -> status='timeout' with disclosure ----------------


def _index_with_text_files(fake_repo, n=5):
    files = {f"f{i}.py": "# TODO: x\nx=1\n" for i in range(n)}
    repo = fake_repo(files, name="deadline-target")
    return repo, build_repo_index(repo).index


def test_todo_markers_expired_deadline_reports_timeout(fake_repo):
    from repo_audit.collectors.todo_markers import run

    repo, index = _index_with_text_files(fake_repo)
    past = time.perf_counter() - 1.0  # already expired
    result = run(repo, index, deadline=past)
    assert result.status == "timeout"
    assert "time budget" in result.notes.lower()


def test_file_size_cap_expired_deadline_reports_timeout(fake_repo):
    from repo_audit.collectors.file_size_cap import run

    repo, index = _index_with_text_files(fake_repo)
    past = time.perf_counter() - 1.0
    result = run(repo, index, deadline=past)
    assert result.status == "timeout"
    assert "time budget" in result.notes.lower()


def test_secret_detection_expired_deadline_reports_timeout(fake_repo):
    from repo_audit.collectors.secret_detection import run

    repo, index = _index_with_text_files(fake_repo)
    past = time.perf_counter() - 1.0
    result = run(repo, index, deadline=past)
    # Truncated sweep takes precedence over the gitleaks-absent 'partial'.
    assert result.status == "timeout"
    assert "time budget" in result.notes.lower()


def test_collectors_no_deadline_still_ok(fake_repo):
    """deadline=None (default) preserves prior behaviour: full sweep, status ok."""
    from repo_audit.collectors.todo_markers import run as todo_run
    from repo_audit.collectors.file_size_cap import run as fsc_run

    repo, index = _index_with_text_files(fake_repo)
    assert todo_run(repo, index).status == "ok"
    assert fsc_run(repo, index).status == "ok"


# --- 3 & 4. DeadlineGuard / remaining_seconds primitives --------------------


def test_deadline_guard_none_never_trips():
    guard = DeadlineGuard(None, check_every=1)
    for _ in range(1000):
        assert guard.tick() is False
    assert guard.tripped is False


def test_deadline_guard_trips_when_past():
    guard = DeadlineGuard(time.perf_counter() - 1.0, check_every=1)
    assert guard.tick() is True
    assert guard.tripped is True


def test_deadline_guard_first_tick_polls_when_already_expired():
    """An already-expired deadline trips on the FIRST tick (collector started late)."""
    guard = DeadlineGuard(time.perf_counter() - 1.0, check_every=256)
    assert guard.tick() is True


def test_deadline_guard_polls_on_interval_not_between():
    """Between the first tick and the next check_every boundary the clock is NOT
    polled, so a deadline that expires mid-interval is only noticed at the boundary.

    Construct with a FUTURE deadline so the first-tick poll does not trip, then
    move the deadline into the past and confirm ticks 2-3 (not on the boundary)
    stay False while tick 4 (the next multiple of check_every=4) polls and trips.
    """
    guard = DeadlineGuard(time.perf_counter() + 1000.0, check_every=4)
    assert guard.tick() is False          # tick 1: future deadline -> no trip
    guard.deadline = time.perf_counter() - 1.0  # deadline now in the past
    assert guard.tick() is False          # tick 2: not a boundary -> not polled
    assert guard.tick() is False          # tick 3: not a boundary -> not polled
    assert guard.tick() is True           # tick 4: 4 % 4 == 0 -> polls -> trips


def test_remaining_seconds_none_and_clamp():
    assert remaining_seconds(None) is None
    assert remaining_seconds(time.perf_counter() - 5.0) == 0.0
    rem = remaining_seconds(time.perf_counter() + 100.0)
    assert rem is not None and 0.0 < rem <= 100.0
