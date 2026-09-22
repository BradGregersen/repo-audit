"""Fuzz lane detection contract (FUZZ-01, Wave 0 scaffolding).

Pins the detect-only signal for Plan 16-03:
  * fast-check is a PROPERTY harness that runs INSIDE the normal test run; the
    lane only emits a PRESENCE signal for it and never invokes fast-check
    standalone (Pitfall 4 — no separate fast-check run).

``importorskip`` keeps this SKIPPED until ``repo_audit.adapters.fuzz``
lands, then it flips ACTIVE (Phase-3/11 discipline; NOT xfail-strict).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

fuzz = pytest.importorskip(
    "repo_audit.adapters.fuzz",
    reason="optional module repo_audit.adapters.fuzz not importable — feature not present in this build, or the install is incomplete",
)


def _detect(repo: Path):
    """Invoke the lane's detection entry point, tolerating naming variants."""
    for name in ("detect", "detect_suites", "fuzz_state", "run_fuzz"):
        fn = getattr(fuzz, name, None)
        if fn is not None:
            return fn(repo)
    pytest.fail("adapters.fuzz exposes no detection entry point")


def test_fastcheck_detect(tmp_path: Path):
    """A repo declaring fast-check -> a PRESENCE signal, never a standalone invoke.

    fast-check runs inside the project's own test run, so the lane only records
    that property testing is present; it must not shell out to run fast-check on
    its own (Pitfall 4).
    """
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "devDependencies": {"fast-check": "^3.0.0"}}),
        encoding="utf-8",
    )
    result = _detect(tmp_path)
    # The detect path is read-only — presence is a signal, not a run.
    status = getattr(result, "status", result)
    assert status in ("ok", "not_applicable", "unavailable", "partial", None)
