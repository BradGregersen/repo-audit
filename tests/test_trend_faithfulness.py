"""Plan 05-03 Task 2 — the load-bearing faithfulness-survival test (RESEARCH Pitfall 1).

The faithfulness gate (``render.faithfulness.build_allowed_numbers``) seeds the
AllowedNumbers set ONLY from Finding ``parsed_value`` leaves + counts. Trend
deltas are NOT findings, so the agent's ``trend_narrative`` numbers
("rose from 120 to 134, up 14") would be silently STRIPPED by the gate unless
``build_allowed_numbers`` folds the TrendDelta magnitudes + prior baseline
totals into the allow-set.

This file proves both halves of the contract:
  * positive — genuine trend numbers (delta + prior + current totals) SURVIVE;
  * negative control — a fabricated number not in the trend is STILL STRIPPED.

T-05-03 (STRIDE Spoofing): the negative control is what makes the fold safe —
we admit ONLY the Python-computed numbers, never a blanket pass.
"""
from __future__ import annotations

from datetime import date

from repo_audit.render.faithfulness import (
    build_allowed_numbers,
    check_faithfulness,
    load_faithfulness_allowlist,
)
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.scope_ledger import ScopeLedger
from repo_audit.schema.report import ReportMeta
from repo_audit.schema.trend import TrendDelta


def _meta() -> ReportMeta:
    return ReportMeta(
        repo_slug="fake-repo",
        commit_sha="UNCOMMITTED",
        scan_date=date(2026, 5, 29),
        tool_version="0.0.0-test",
    )


def _ledger() -> ScopeLedger:
    return ScopeLedger(scanned=[], skipped=[], unavailable=[])


def _cadence_finding(commits_total: int) -> Finding:
    """Current-scan cadence finding — its commits_total is the 'current' total.

    The current total ('to 134') traces to this finding's parsed_value leaf;
    the prior total ('from 120') + the delta ('up 14') trace to the TrendDelta
    fold. All three together let the full movement sentence survive.
    """
    return Finding(
        dimension="process",
        severity="info",
        evidence_type="static",
        confidence="high",
        source_tool="pygit2",
        source_collector="git_cadence",
        evidence=Evidence(tool="pygit2", parsed_value={"commits_total": commits_total}),
    )


def _trend() -> TrendDelta:
    """Prior 120 commits → current 134 commits, +14. Prior total exposed."""
    return TrendDelta(
        prior_baseline_date=date(2026, 5, 1),
        commits_delta=14,
        loc_delta=None,
        lint_error_delta=None,
        coverage_delta=None,
        finding_count_delta_by_dimension={},
        prior_totals={"commits": 120},
    )


def test_delta_numbers_in_allowed():
    """The delta (14), prior total (120), and current total (134) are all admitted."""
    findings = [_cadence_finding(134)]
    allowed = build_allowed_numbers(findings, _ledger(), _meta(), trend=_trend())
    assert 14.0 in allowed  # delta magnitude (folded from TrendDelta)
    assert 120.0 in allowed  # prior baseline total (folded from prior_totals)
    assert 134.0 in allowed  # current total (finding parsed_value leaf)


def test_trend_narrative_survives_gate():
    """LOAD-BEARING (Pitfall 1): a real movement sentence is KEPT, not stripped.

    This is exactly the kind of sentence the agent emits into
    AgentScanReport.trend_narrative. With the trend fold, every numeric token
    traces back to the allow-set, so the gate keeps the whole sentence.
    """
    findings = [_cadence_finding(134)]
    allowed = build_allowed_numbers(findings, _ledger(), _meta(), trend=_trend())
    trigger, allowlist = load_faithfulness_allowlist()

    prose = "Commits rose from 120 to 134, up 14 since the prior report."
    clean, violations = check_faithfulness(prose, allowed, trigger, allowlist)

    assert violations == []
    assert "120" in clean and "134" in clean and "14" in clean
    assert "elided" not in clean.lower()


def test_fabricated_trend_number_still_stripped():
    """NEGATIVE CONTROL (T-05-03): a number NOT in the trend is still stripped.

    The fold admits ONLY the Python-computed trend numbers — it must not blanket-
    pass any number in a trend sentence. 999 appears nowhere in the trend or the
    finding store, so its sentence strips.
    """
    findings = [_cadence_finding(134)]
    allowed = build_allowed_numbers(findings, _ledger(), _meta(), trend=_trend())
    trigger, allowlist = load_faithfulness_allowlist()

    prose = "The repository gained 999 phantom commits overnight."
    clean, violations = check_faithfulness(prose, allowed, trigger, allowlist)

    assert len(violations) == 1
    assert any("999" in t for t in violations[0].offending_tokens)
    assert clean.strip() == "" or "elided" in clean.lower()


def test_mixed_real_and_fabricated_strips_only_fabricated():
    """A real movement sentence survives even when a sibling fabricated sentence strips."""
    findings = [_cadence_finding(134)]
    allowed = build_allowed_numbers(findings, _ledger(), _meta(), trend=_trend())
    trigger, allowlist = load_faithfulness_allowlist()

    prose = (
        "Commits rose from 120 to 134, up 14 since the prior report. "
        "Coverage also jumped to 88 percent."
    )
    clean, violations = check_faithfulness(prose, allowed, trigger, allowlist)

    # The real movement sentence is kept; the fabricated 88 sentence strips.
    assert "from 120 to 134" in clean
    assert len(violations) == 1
    assert any("88" in t for t in violations[0].offending_tokens)


def test_none_trend_leaves_allowed_unchanged():
    """trend=None (baseline run) → no trend numbers folded; behavior unchanged."""
    findings = [_cadence_finding(134)]
    allowed_with_none = build_allowed_numbers(findings, _ledger(), _meta(), trend=None)
    # 120 (prior total) must NOT be present without a trend.
    assert 120.0 not in allowed_with_none
    # 134 still present (it is a finding leaf, not a trend number).
    assert 134.0 in allowed_with_none
