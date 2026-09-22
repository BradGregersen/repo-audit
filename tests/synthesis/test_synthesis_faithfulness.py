"""SYN-02 — `why_it_matters` citing the composite/driver survives the faithfulness
gate; an invented number is still stripped (negative control).

Clones the `tests/test_trend_faithfulness.py` AllowedNumbers-fold pattern (T-18-09):
the synthesis fold admits ONLY the Python-computed Top-N magnitudes, never a
blanket pass — so a genuine composite citation survives while a fabricated number
strips. The negative control is what makes the fold safe.

Both the synthesis-side helper (`synthesis.faithfulness`) and the render-layer
`build_allowed_numbers` Top-N fold are exercised.
"""
from __future__ import annotations

from datetime import date

import pytest

_faith = pytest.importorskip(
    "repo_audit.synthesis.faithfulness",
    reason="optional module repo_audit.synthesis.faithfulness not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.agent.schema import TopFinding
from repo_audit.render.faithfulness import (
    build_allowed_numbers,
    check_faithfulness,
    load_faithfulness_allowlist,
)
from repo_audit.schema.report import ReportMeta
from repo_audit.schema.scope_ledger import ScopeLedger
from repo_audit.synthesis.record import PriorityScore


def test_composite_folded_invented_stripped():
    """A narration citing the real composite/epss survives; an invented strips."""
    allowed = _faith.allowed_numbers_for_score(composite=0.42, epss=0.9)
    assert 0.42 in allowed
    cleaned = _faith.strip_unfaithful_numbers(
        "Composite 0.42 with EPSS 0.9 matters. But an invented 842 lurks here.",
        allowed,
    )
    assert "0.42" in cleaned
    assert "842" not in cleaned


def _meta() -> ReportMeta:
    return ReportMeta(
        repo_slug="fake-repo",
        commit_sha="UNCOMMITTED",
        scan_date=date(2026, 6, 5),
        tool_version="0.0.0-test",
    )


def test_build_allowed_numbers_folds_top_findings():
    """The render-layer fold admits composite + factor magnitudes + epss."""
    tf = TopFinding(
        rank=1,
        finding_ref="osv::CVE-X::a.ts:1",
        severity="critical",
        confidence="confirmed",
        composite=0.62,
        band=1,
    )
    score = PriorityScore(
        candidate_token=0,
        severity_w=0.95,
        confidence_w=0.8,
        exploitability_w=0.55,
        blast_radius_w=0.5,
        composite=0.62,
        epss=0.91,
        band=1,
    )
    allowed = build_allowed_numbers(
        [], ScopeLedger(scanned=[], skipped=[], unavailable=[]), _meta(),
        top_findings=[tf], top_scores=[score],
    )
    assert 0.62 in allowed  # composite
    assert 0.95 in allowed  # severity_w
    assert 0.55 in allowed  # exploitability_w
    assert 0.91 in allowed  # epss

    # A why_it_matters sentence citing the composite SURVIVES the gate...
    trigger, allowlist = load_faithfulness_allowlist()
    clean, viol = check_faithfulness(
        "This finding scores composite 0.62 driven by exploitability.",
        allowed, trigger, allowlist,
    )
    assert "0.62" in clean
    assert viol == []

    # ...while a fabricated number (NOT folded) is still stripped.
    clean2, viol2 = check_faithfulness(
        "The composite mysteriously reads 738 here.",
        allowed, trigger, allowlist,
    )
    assert len(viol2) == 1
