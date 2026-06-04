"""SAFE-08 first-class degrade contracts (Plan 15-01, Task 2) — SCAFFOLD.

Pins the two first-class degrade paths the Wave-1 collectors (Plans 02/03) MUST
honor — written FAILING-by-design as importorskip-gated scaffolds so they SKIP
cleanly NOW (the collector symbols are absent in this Wave-0 skeleton) and flip
ACTIVE automatically the instant Plans 02/03 land the collectors (the Phase-3
SKIPPED→ACTIVE-on-landing discipline). They must NEVER ERROR.

Degrade contract 1 (web, D-15-03): no ``live_url`` configured → ``collect_axe`` /
``collect_lighthouse`` return ``status="unavailable"`` WITHOUT invoking any binary
(no network egress); the scan still completes.

Degrade contract 2 (RN, D-15 / SAFE-08): no ``qd_build`` flag AND no existing
bundle artifact → ``collect_rn_bundle`` returns ``status="unavailable"`` (the
build is opt-in; absent opt-in + absent artifact → honest degrade).
"""
from __future__ import annotations

from pathlib import Path

import pytest

# Wave-1 collector symbols live on the package namespace once Plans 02/03 land.
# importorskip the package, then skip per-test if the specific collector is
# still absent — so this whole module SKIPS cleanly in Wave 0, never ERRORS.
qd = pytest.importorskip(
    "repo_audit.adapters.quality_depth",
    reason="quality_depth package missing",
)

_HAS_AXE = hasattr(qd, "collect_axe")
_HAS_LIGHTHOUSE = hasattr(qd, "collect_lighthouse")
_HAS_RN_BUNDLE = hasattr(qd, "collect_rn_bundle")


@pytest.mark.skipif(
    not _HAS_AXE,
    reason="Wave 1 (Plan 02) not yet landed — quality_depth.collect_axe missing",
)
def test_no_live_url_axe_degrades_unavailable(tmp_path: Path) -> None:
    """No live_url → collect_axe degrades to unavailable WITHOUT egress."""
    result = qd.collect_axe(  # type: ignore[attr-defined]
        tmp_path, {}, live_url=None, timeout_seconds=120
    )
    assert result.status == "unavailable"


@pytest.mark.skipif(
    not _HAS_LIGHTHOUSE,
    reason="Wave 1 (Plan 03) not yet landed — quality_depth.collect_lighthouse missing",
)
def test_no_live_url_lighthouse_degrades_unavailable(tmp_path: Path) -> None:
    """No live_url → collect_lighthouse degrades to unavailable WITHOUT egress."""
    result = qd.collect_lighthouse(  # type: ignore[attr-defined]
        tmp_path, {}, live_url=None, timeout_seconds=120
    )
    assert result.status == "unavailable"


@pytest.mark.skipif(
    not _HAS_RN_BUNDLE,
    reason="Wave 1 (Plan 03) not yet landed — quality_depth.collect_rn_bundle missing",
)
def test_no_build_no_artifact_rn_bundle_degrades_unavailable(tmp_path: Path) -> None:
    """No qd_build AND no existing bundle artifact → rn_bundle unavailable."""
    result = qd.collect_rn_bundle(  # type: ignore[attr-defined]
        tmp_path, {}, qd_build=False, timeout_seconds=900
    )
    assert result.status == "unavailable"
