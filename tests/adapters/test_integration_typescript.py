"""Phase 3 integration tests — TWO module-level gates.

1. ``pytest.importorskip("repo_audit.adapters")`` — SKIP until Wave 1 lands.
2. ``pytestmark = pytest.mark.integration`` — SKIP under default ``pytest -q``;
   opt-in via ``pytest -m integration``.

Default suite (``pytest -q``) skips on (1) until Wave 1 lands; once Wave 1
lands, default suite skips on (2). Live integration runs require an actual
TS toolchain in ``<repo>/node_modules/.bin/`` (verified live in 03-RESEARCH
against ``/path/to/example-app``).

The canonical SC-6 live-binary check (``test_post_scan_repo_clean``) lives
here per checker Warning 10. A host-independent unit-test counterpart lives
at ``tests/adapters/test_post_scan_repo_clean_unit.py``.
"""
from __future__ import annotations

import subprocess

import pytest

pytest.importorskip(
    "repo_audit.adapters",
    reason="Wave 1 (plan 03-02) not yet landed — adapters package missing",
)

# Both gates apply: importorskip miss OR missing integration marker ⇒ SKIP.
pytestmark = pytest.mark.integration

from repo_audit.adapters import run_adapters  # noqa: E402
from repo_audit.detect.detector import detect_stacks  # noqa: E402


def test_full_scan_emits_real_findings(ts_fixture_repo):
    """End-to-end: a TS fixture repo with real tsc/eslint/knip in node_modules
    produces a non-empty results list."""
    detection = detect_stacks(ts_fixture_repo)
    results = run_adapters(ts_fixture_repo, detection)
    assert len(results) >= 1


def test_post_scan_repo_clean(ts_fixture_repo):
    """SC-6 / D-46 LIVE-BINARY check: post-scan ``git status --porcelain`` is empty.

    This is the canonical location per checker Warning 10. The unit-test
    counterpart at ``test_post_scan_repo_clean_unit.py`` provides the same
    structural guarantee under pytest-subprocess mocking so the default suite
    can verify SC-6 without a live toolchain.
    """
    detection = detect_stacks(ts_fixture_repo)
    run_adapters(ts_fixture_repo, detection)
    cp = subprocess.run(
        ["git", "-C", str(ts_fixture_repo), "status", "--porcelain"],
        capture_output=True, text=True, check=True,
    )
    offenders = [
        line for line in cp.stdout.splitlines()
        if line.strip()
        and "docs/state-reports" not in line
        and "coverage/" not in line
    ]
    assert offenders == [], (
        f"SC-6 violated — files outside permitted surfaces: {offenders}"
    )


def test_scope_ledger_includes_adapter_unavailable_rows(ts_fixture_repo_no_lcov):
    """When a tool is unavailable (lcov missing), the scope ledger must surface it."""
    detection = detect_stacks(ts_fixture_repo_no_lcov)
    results = run_adapters(ts_fixture_repo_no_lcov, detection)
    # Coverage adapter should report unavailable
    cov_results = [r for r in results if r.source_tool == "coverage_lcov"]
    assert len(cov_results) == 1
    assert cov_results[0].status == "unavailable"
