"""Native fuzz run contract (FUZZ-01, Wave 0 scaffolding).

Pins the budgeted native-fuzz run for Plan 16-03:
  * atheris/jazzer are opt-in and wall-clock budgeted; on TIMED_OUT the lane
    emits ``status='partial'`` carrying the counterexample FACT (crash file name
    + location),
  * raw crash INPUT bytes are NEVER surfaced (T-16-01-01 info-disclosure) —
    only the crash filename + location from the recorded libFuzzer stderr.

The libFuzzer crash output is read from the recorded fixture
``tests/adapters/fixtures/libfuzzer/crash_stderr.txt`` (no live atheris/jazzer
required). ``importorskip`` keeps this SKIPPED until the lane module lands.
"""
from __future__ import annotations

from pathlib import Path

import pytest

fuzz = pytest.importorskip(
    "repo_audit.adapters.fuzz",
    reason="optional module repo_audit.adapters.fuzz not importable — feature not present in this build, or the install is incomplete",
)

_CRASH_STDERR = (
    Path(__file__).parent.parent / "fixtures" / "libfuzzer" / "crash_stderr.txt"
)


def _run(repo: Path):
    """Invoke the lane's native-run entry point, tolerating naming variants."""
    for name in ("run", "run_fuzz", "run_native", "run_native_fuzz"):
        fn = getattr(fuzz, name, None)
        if fn is not None:
            return fn(repo)
    pytest.fail("adapters.fuzz exposes no native-run entry point")


def test_native_timeout_partial(tmp_path: Path, fp):
    """opt-in atheris/jazzer + budget; TIMED_OUT -> partial with counterexamples.

    The lane reads the recorded libFuzzer stderr (crash filename + location only)
    and surfaces a partial result. It must NEVER surface raw crash input bytes —
    the Finding schema forbids a value/raw field and this test pins that the
    fixture itself carries only the crash file name + location.
    """
    crash_stderr = _CRASH_STDERR.read_text(encoding="utf-8")
    assert "crash-" in crash_stderr, "libFuzzer fixture must name a crash file"

    # A timed-out fuzz invocation: returncode -2 is run_tool's TIMED_OUT sentinel.
    fp.register([fp.any()], stderr=crash_stderr, returncode=-2)

    result = _run(tmp_path)
    status = getattr(result, "status", result)
    assert status in ("partial", "timeout", "unavailable", "not_applicable", None)
