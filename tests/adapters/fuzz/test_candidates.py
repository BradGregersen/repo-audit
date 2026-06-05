"""Un-fuzzed-surface candidate signal (FUZZ-01, Wave 0 scaffolding).

Pins the candidate-surface heuristic for Plan 16-03:
  * the lane surfaces un-fuzzed code surfaces as CANDIDATE signals (a hint that a
    surface could be fuzzed), NEVER a generated fuzz target and NEVER a confident
    finding.

``importorskip`` keeps this SKIPPED until ``repo_audit.adapters.fuzz``
lands, then it flips ACTIVE (Phase-3/11 discipline; NOT xfail-strict).
"""
from __future__ import annotations

from pathlib import Path

import pytest

fuzz = pytest.importorskip(
    "repo_audit.adapters.fuzz",
    reason="Wave 1/2 (plan 16-03) not yet landed — adapters.fuzz missing",
)


def _candidates(repo: Path):
    """Invoke the lane's candidate-surface entry point, tolerating naming variants."""
    for name in (
        "candidates",
        "candidate_surfaces",
        "unfuzzed_candidates",
        "detect_candidates",
    ):
        fn = getattr(fuzz, name, None)
        if fn is not None:
            return fn(repo)
    pytest.fail("adapters.fuzz exposes no candidate-surface entry point")


def test_unfuzzed_surface_candidate_signal(tmp_path: Path):
    """An un-fuzzed parser surface -> a CANDIDATE signal, never a generated target.

    The lane reads the repo (read-only) and may emit candidate-confidence signals
    pointing at surfaces that look fuzzable. It must never write a fuzz target
    into the repo.
    """
    (tmp_path / "parser.py").write_text(
        "def parse(data: bytes):\n    return data.decode()\n", encoding="utf-8"
    )
    before = {p.name for p in tmp_path.rglob("*")}
    result = _candidates(tmp_path)
    after = {p.name for p in tmp_path.rglob("*")}

    # Read-only: never generates a target file.
    assert after == before
    # Any findings surfaced are candidate-confidence only.
    findings = getattr(result, "findings", None)
    if findings:
        assert all(f.confidence == "candidate" for f in findings)
