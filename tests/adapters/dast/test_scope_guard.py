"""DAST scope-guard contract (DAST-01, Wave 0 scaffolding).

Pins the LOAD-BEARING safety property for Plan 16-05:
  * with no ``dast.target_url`` configured, the lane is ``unavailable`` and NEVER
    scans — it never infers/derives a target,
  * the configured ``cfg.target_url`` is the ONLY assignment that can reach the
    ZAP ``-t`` argv: a source-string grep forbids ``localhost`` / ``homepage`` /
    ``--dast-url`` tokens in the DAST module so a target can never be synthesised
    from anything but the explicit config.

``importorskip`` keeps these SKIPPED until ``repo_audit.adapters.dast``
lands, then they flip ACTIVE (Phase-3/11 discipline; NOT xfail-strict).
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

dast = pytest.importorskip(
    "repo_audit.adapters.dast",
    reason="optional module repo_audit.adapters.dast not importable — feature not present in this build, or the install is incomplete",
)


def _run(repo: Path, cfg=None):
    """Invoke the lane's run entry point, tolerating naming variants."""
    for name in ("run", "run_dast"):
        fn = getattr(dast, name, None)
        if fn is not None:
            return fn(repo) if cfg is None else fn(repo, cfg)
    pytest.fail("adapters.dast exposes no run entry point")


def test_no_target_unavailable(tmp_path: Path):
    """No ``dast.target_url`` -> ``unavailable``, never scans.

    Absent an explicit target the lane must short-circuit to unavailable and not
    invoke ZAP at all (it must never derive a host).
    """
    result = _run(tmp_path)
    status = getattr(result, "status", result)
    assert status in ("unavailable", "not_applicable")
    note = (getattr(result, "notes", "") or "").lower()
    assert "target" in note or "url" in note or "configured" in note


def test_target_single_source():
    """SOURCE-STRING grep: ``cfg.target_url`` is the ONLY target source.

    The DAST module must not contain any token that could synthesise a target
    from something other than the explicit config — no ``localhost``, no
    ``homepage``, no ``--dast-url`` flag. This makes the single-source guard a
    STRUCTURAL property of the source, not just a runtime check.
    """
    source = inspect.getsource(dast)
    lowered = source.lower()
    for forbidden in ("localhost", "homepage", "--dast-url"):
        assert forbidden not in lowered, (
            f"DAST module must not reference {forbidden!r} — "
            "target_url is the ONLY permitted target source"
        )
    # The explicit config field is referenced as the target source.
    assert "target_url" in source
