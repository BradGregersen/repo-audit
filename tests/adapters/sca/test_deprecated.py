"""SCA-04 — deprecated/abandoned package handling (Wave 1).

Wave-0 ``importorskip`` stub: SKIPPED until the SCA-04 deprecated module lands
(``repo_audit.adapters.sca.deprecated``), then ACTIVE.

Contract under test (D-12-08 + no-dilution):
  * a deprecated/abandoned package surfaces as INFO-level CONTEXT, NOT a
    fix-generating finding (no ``recommendation`` that says "upgrade to X").

The deprecated signal is informational only; it must never be promoted to a
remediation finding the way a CVE/MAL finding is.
"""
from __future__ import annotations

import pytest

deprecated = pytest.importorskip(
    "repo_audit.adapters.sca.deprecated",
    reason="Wave 1 not yet landed — sca.deprecated missing",
)


def _classify(packages):
    """Invoke the Wave-1 deprecated-package classifier, tolerating names."""
    for name in (
        "classify_deprecated",
        "deprecated_context",
        "collect_deprecated",
    ):
        fn = getattr(deprecated, name, None)
        if fn is not None:
            return fn(packages)
    pytest.fail("sca.deprecated exposes no deprecated-package entry point")


def test_deprecated_is_info_context_not_finding():
    """A deprecated package yields INFO context, not a fix-generating finding."""
    # Minimal synthetic input; Wave 1 owns the exact package-record shape.
    packages = [{"name": "left-pad", "version": "1.0.0", "deprecated": True}]
    result = _classify(packages)
    findings = getattr(result, "findings", result)
    for f in findings:
        assert f.severity == "info", (
            f"deprecated must be info-level context, got {f.severity!r}"
        )
        rec = (getattr(f, "recommendation", "") or "").lower()
        assert "upgrade to" not in rec, (
            "deprecated context must not generate an upgrade-to fix recommendation"
        )
