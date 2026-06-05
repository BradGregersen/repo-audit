"""CodeQL default-OFF gate contract (DSAST-01, Wave 0 scaffolding).

Pins the load-bearing default-OFF posture for Plan 16-04:
  * with no attestation, CodeQL NEVER runs and the lane reports ``unavailable`` —
    a heavy security scanner is never invoked implicitly.

``importorskip`` keeps this SKIPPED until ``repo_audit.adapters.codeql``
lands, then it flips ACTIVE (Phase-3/11 discipline; NOT xfail-strict).
"""
from __future__ import annotations

from pathlib import Path

import pytest

codeql = pytest.importorskip(
    "repo_audit.adapters.codeql",
    reason="Wave 1/2 (plan 16-04) not yet landed — adapters.codeql missing",
)


def _run(repo: Path, cfg=None):
    """Invoke the lane's run entry point, tolerating naming variants."""
    for name in ("run", "run_codeql"):
        fn = getattr(codeql, name, None)
        if fn is not None:
            return fn(repo) if cfg is None else fn(repo, cfg)
    pytest.fail("adapters.codeql exposes no run entry point")


def test_default_off(tmp_path: Path):
    """No attestation -> CodeQL never runs, status ``unavailable``.

    The default posture is OFF: absent an explicit enable + use-rights
    attestation, the lane must not create a CodeQL DB or analyze, and must report
    unavailable with a note naming the gate.
    """
    result = _run(tmp_path)
    status = getattr(result, "status", result)
    assert status == "unavailable"
    note = (getattr(result, "notes", "") or "").lower()
    assert "attest" in note or "default" in note or "off" in note or "enable" in note
