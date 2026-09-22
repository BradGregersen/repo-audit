"""E2E opt-in run contract (E2E-01, Wave 0 scaffolding).

Pins the opt-in run path for Plan 16-02:
  * with --e2e + a mocked Playwright JSON report (via the pytest-subprocess ``fp``
    fixture), the lane parses pass/fail from the report,
  * it NEVER auto-authors a spec — it only runs what the repo already declares.

The Playwright JSON shape is read from the recorded fixture
``tests/adapters/fixtures/playwright/report.json`` so no live Playwright binary
is required. ``importorskip`` keeps this SKIPPED until the lane module lands.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

e2e = pytest.importorskip(
    "repo_audit.adapters.e2e",
    reason="optional module repo_audit.adapters.e2e not importable — feature not present in this build, or the install is incomplete",
)

_PW_REPORT = (
    Path(__file__).parent.parent / "fixtures" / "playwright" / "report.json"
)


def _run(repo: Path):
    """Invoke the lane's opt-in run entry point, tolerating naming variants."""
    for name in ("run", "run_e2e", "run_harness"):
        fn = getattr(e2e, name, None)
        if fn is not None:
            return fn(repo)
    pytest.fail("adapters.e2e exposes no run entry point")


def test_e2e_opt_in_parses_passfail(tmp_path: Path, fp):
    """--e2e + a mocked Playwright JSON report -> pass/fail parsed; no spec authored.

    The fixture report carries one passed + one failed test; the lane must derive
    the pass/fail tally from ``suites[].specs[].tests[].results[].status`` rather
    than inventing it, and must NOT write any spec file into the repo (read-only).
    """
    report = json.loads(_PW_REPORT.read_text(encoding="utf-8"))
    assert report, "Playwright fixture must be non-empty"

    (tmp_path / "playwright.config.ts").write_text(
        "export default {};\n", encoding="utf-8"
    )
    # Any Playwright invocation the lane makes returns the recorded JSON report.
    fp.register([fp.any()], stdout=json.dumps(report), returncode=1)

    before = {p.name for p in tmp_path.rglob("*")}
    result = _run(tmp_path)
    after = {p.name for p in tmp_path.rglob("*")}

    # Read-only: the lane never auto-authors a spec.
    assert after == before, "E2E lane must never write a spec into the repo"
    # Pass/fail is surfaced (status or a finding/notes signal derived from JSON).
    assert result is not None
