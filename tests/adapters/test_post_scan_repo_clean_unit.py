"""SC-6 host-independent unit test (checker Blocker 6).

Validates the D-46 cache-redirection contract WITHOUT requiring the
``/path/to/example-app`` fleet (or any live TS toolchain) to be present. The
full integration test at
``tests/adapters/test_integration_typescript.py::test_post_scan_repo_clean``
stays as a separate live-binary check (gated by ``-m integration``).

Module-level ``importorskip`` so this test SKIPS in Wave 0 and flips ACTIVE
once Wave 1 / Wave 2 land. NOT marked integration — it runs in the default
``uv run pytest -q`` suite once active.
"""
from __future__ import annotations

import subprocess

import pytest

pytest.importorskip(
    "repo_audit.adapters",
    reason="optional module repo_audit.adapters not importable — feature not present in this build, or the install is incomplete",
)
pytest.importorskip(
    "repo_audit.adapters.typescript",
    reason="optional module repo_audit.adapters.typescript not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.adapters import run_adapters  # noqa: E402
from repo_audit.detect.detector import detect_stacks  # noqa: E402


def test_post_scan_repo_clean_unit(ts_fixture_repo, mock_ts_tools_subprocess):
    """Build a git-init tmp TS repo, mock tsc/eslint/knip, run the adapter,
    assert no files outside ``docs/state-reports/`` + ``coverage/`` appear in
    ``git status --porcelain`` after the scan."""
    mock_ts_tools_subprocess(tsc="clean", eslint="clean", knip="clean")

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
