"""Shared per-collector wall-clock bounding (SCAN-BOUND-01 follow-up / 05.1-gap).

The between-collector deadline in ``run_collectors`` (D-051-06) cannot interrupt
a single collector once it has started. On a very large repo (e.g. the 40 GB
``adapt`` monorepo) the content-read / subprocess collectors each traverse the
whole index with their own generous individual bounds and so run unbounded
*inside* their own body:

    * secret_detection -> calls ``scan_with_gitleaks(text)`` ONCE PER FILE when
      gitleaks is on PATH (a subprocess spawn per text file). On adapt's ~13.7 k
      indexed files this never finishes inside the 120 s canary (measured: SIGKILL
      past 200 s). This is THE Blocker-A bottleneck.
    * todo_markers   -> reads CONTENT of every indexed text file (~9 s on adapt).
    * file_size_cap  -> streams every in-cap file to count lines (~4 s on adapt).
    * loc_inventory  -> scc subprocess walking the tree itself.

This module gives those collectors the tools to bound themselves by the SHARED
scan deadline (a ``time.perf_counter`` value — the SAME clock ``run_collectors``
and ``run_scan`` use):

    * ``remaining_seconds(deadline)`` -> seconds left before the scan deadline
      (``None`` when no deadline; ``0.0`` when already past). Subprocess
      collectors cap their tool timeout at this value so a child process can
      never run past the scan budget.
    * ``DeadlineGuard`` -> a cheap, periodically-polled wall-clock check a
      content loop calls once per file; flips ``tripped`` when the deadline is
      reached so the loop can ``break`` and self-report.

Whenever a bound trips, the caller marks its ``CollectorResult.status`` as
``'timeout'`` with an honest ``notes`` string. A ``status != 'ok'`` result
already flows to the scope ledger's unavailable section and flips the scan to
partial (D-31 / SAFE-08) — coverage is bounded but NEVER silently dropped.
"""

from __future__ import annotations

import time

# How often (in files) a content loop polls the wall-clock deadline. Polling is
# a single perf_counter() call; once per N files keeps the overhead negligible
# while still reacting within a fraction of a second on any realistic file size.
_DEADLINE_CHECK_EVERY: int = 256


def remaining_seconds(deadline: float | None) -> float | None:
    """Seconds remaining before ``deadline`` (a ``time.perf_counter`` value).

    Returns ``None`` when ``deadline`` is ``None`` (no bound — preserves prior
    behaviour for every existing caller/test), and ``0.0`` when the deadline has
    already passed (caller treats a non-positive value as "no time left").
    """
    if deadline is None:
        return None
    return max(0.0, deadline - time.perf_counter())


class DeadlineGuard:
    """Periodically-polled wall-clock guard for a per-file content loop.

    Call :meth:`tick` once per iteration; it only reads the clock every
    ``check_every`` calls (cheap). When the deadline is reached ``tripped`` is
    set and :meth:`tick` returns ``True`` so the caller can ``break`` and report
    ``status='timeout'``. With ``deadline=None`` the guard never trips, so
    existing callers/tests that pass no deadline keep their exact behaviour.
    """

    __slots__ = ("deadline", "check_every", "_i", "tripped")

    def __init__(self, deadline: float | None, *, check_every: int = _DEADLINE_CHECK_EVERY):
        self.deadline = deadline
        self.check_every = check_every
        self._i = 0
        self.tripped = False

    def tick(self) -> bool:
        """Advance one iteration; return True when the deadline has been reached.

        Polls the clock on the FIRST tick (so an already-expired deadline trips
        immediately — the common case when a collector starts after the budget
        is spent) and every ``check_every`` ticks thereafter (cheap steady
        state). With ``deadline=None`` it never trips.
        """
        if self.deadline is None or self.tripped:
            return self.tripped
        self._i += 1
        if (self._i == 1 or self._i % self.check_every == 0) and (
            time.perf_counter() >= self.deadline
        ):
            self.tripped = True
        return self.tripped
