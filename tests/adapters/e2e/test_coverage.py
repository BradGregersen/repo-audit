"""E2E best-effort coverage contract (E2E-01 / D-16-03, Wave 0 scaffolding).

Pins the coverage policy for Plan 16-02:
  * coverage is BEST-EFFORT — parsed only where the harness emits it cheaply,
  * with no instrumentation present, coverage is reported ``unavailable``,
    NEVER fabricated and NEVER produced by instrumenting/modifying the repo.

``importorskip`` keeps this SKIPPED until ``repo_audit.adapters.e2e`` lands.
"""
from __future__ import annotations

from pathlib import Path

import pytest

e2e = pytest.importorskip(
    "repo_audit.adapters.e2e",
    reason="Wave 1/2 (plan 16-02) not yet landed — adapters.e2e missing",
)


def _coverage(repo: Path):
    """Invoke the lane's coverage entry point, tolerating naming variants."""
    for name in ("coverage", "e2e_coverage", "parse_coverage", "best_effort_coverage"):
        fn = getattr(e2e, name, None)
        if fn is not None:
            return fn(repo)
    pytest.fail("adapters.e2e exposes no coverage entry point")


def test_coverage_best_effort_else_unavailable(tmp_path: Path):
    """No instrumentation present -> coverage ``unavailable`` (D-16-03), never invented.

    The lane must not instrument the repo to produce coverage; absent a cheap
    harness-emitted coverage artifact, it honestly reports unavailable.
    """
    (tmp_path / "playwright.config.ts").write_text(
        "export default {};\n", encoding="utf-8"
    )
    result = _coverage(tmp_path)
    status = getattr(result, "status", result)
    # No coverage artifact + no instrumentation => unavailable, not a number.
    assert status in ("unavailable", "not_applicable", None)
    # If a coverage value is exposed it must be None (never a fabricated pct).
    pct = getattr(result, "coverage_pct", None)
    assert pct is None
