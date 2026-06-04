"""PERF-01 web tier — lighthouse_json aggregate mapper contract (Plan 15-03, Task 1).

Pins the LHR -> aggregate Finding contract: ONE ``lighthouse_perf_summary`` Finding
carrying ``web_transfer_bytes`` + LCP/CLS/TBT/score in ``parsed_value`` (aggregate,
NOT one-per-audit), plus INDEPENDENT ``web_transfer_oversized`` and
``web_transfer_regression`` triggers. All findings runtime/candidate, severity <=
major (SCH-04 safe), verify-phrasing self-enforced (the D-15-07 runtime-exemption
trap — these are runtime findings the shared tripwire would not police).
"""
from __future__ import annotations

import re

from repo_audit.adapters.quality_depth import lighthouse_json
from repo_audit.adapters.quality_depth.config import QualityDepthConfig

_BANNED = re.compile(r"\b(enforced|secure|protected)\b", re.IGNORECASE)


def _by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


def test_one_aggregate_summary_under_budget_no_prior(load_json) -> None:
    """A small LHR under budget with no prior yields exactly ONE summary finding."""
    doc = {
        "categories": {"performance": {"score": 0.95}},
        "audits": {
            "largest-contentful-paint": {"numericValue": 1200.0},
            "cumulative-layout-shift": {"numericValue": 0.02},
            "total-blocking-time": {"numericValue": 80.0},
            "total-byte-weight": {"numericValue": 100000.0},
        },
    }
    cfg = QualityDepthConfig()
    findings = lighthouse_json.map_lighthouse_json(doc, config=cfg)
    summaries = _by_rule(findings, "lighthouse_perf_summary")
    assert len(summaries) == 1
    assert len(findings) == 1  # nothing else: under budget, no prior


def test_summary_parsed_value_carries_web_transfer_bytes(load_json) -> None:
    """parsed_value web_transfer_bytes == total-byte-weight numericValue (int)."""
    doc = load_json("lighthouse_lhr.json")
    cfg = QualityDepthConfig()
    findings = lighthouse_json.map_lighthouse_json(doc, config=cfg)
    summary = _by_rule(findings, "lighthouse_perf_summary")[0]
    pv = summary.evidence.parsed_value
    assert pv["web_transfer_bytes"] == 3145728
    assert isinstance(pv["web_transfer_bytes"], int)
    # carrier keys all present
    assert pv["lcp_ms"] == 4800
    assert pv["cls"] == 0.18
    assert pv["tbt_ms"] == 620
    assert pv["perf_score"] == 0.42
    assert "faithful_severity" in pv


def test_summary_severity_minor_when_score_below_half(load_json) -> None:
    """perf_score 0.42 (< 0.5) → minor summary."""
    doc = load_json("lighthouse_lhr.json")
    summary = _by_rule(
        lighthouse_json.map_lighthouse_json(doc, config=QualityDepthConfig()),
        "lighthouse_perf_summary",
    )[0]
    assert summary.severity == "minor"


def test_summary_info_when_score_above_half() -> None:
    """perf_score >= 0.5 → info summary."""
    doc = {
        "categories": {"performance": {"score": 0.8}},
        "audits": {"total-byte-weight": {"numericValue": 50000.0}},
    }
    summary = _by_rule(
        lighthouse_json.map_lighthouse_json(doc, config=QualityDepthConfig()),
        "lighthouse_perf_summary",
    )[0]
    assert summary.severity == "info"


def test_oversized_fires_above_budget(load_json) -> None:
    """total-byte-weight (3 MB) > web_budget_bytes (256000) → oversized finding."""
    doc = load_json("lighthouse_lhr.json")
    findings = lighthouse_json.map_lighthouse_json(doc, config=QualityDepthConfig())
    oversized = _by_rule(findings, "web_transfer_oversized")
    assert len(oversized) == 1
    assert oversized[0].severity == "minor"


def test_no_oversized_under_budget() -> None:
    """Under budget → no oversized finding."""
    doc = {
        "categories": {"performance": {"score": 0.9}},
        "audits": {"total-byte-weight": {"numericValue": 100000.0}},
    }
    findings = lighthouse_json.map_lighthouse_json(doc, config=QualityDepthConfig())
    assert _by_rule(findings, "web_transfer_oversized") == []


def test_regression_fires_only_with_prior_past_both_gates() -> None:
    """prior set so growth > 10% AND > 10240 bytes → regression finding."""
    # current 200000, prior 100000 → +100% and +100000 bytes (past both gates),
    # still under the 256000 budget so this isolates the regression trigger.
    doc = {
        "categories": {"performance": {"score": 0.9}},
        "audits": {"total-byte-weight": {"numericValue": 200000.0}},
    }
    findings = lighthouse_json.map_lighthouse_json(
        doc, config=QualityDepthConfig(), prior_web_bytes=100000
    )
    reg = _by_rule(findings, "web_transfer_regression")
    assert len(reg) == 1
    assert reg[0].severity == "minor"


def test_no_regression_without_prior() -> None:
    """No prior → no regression finding (baseline run)."""
    doc = {
        "categories": {"performance": {"score": 0.9}},
        "audits": {"total-byte-weight": {"numericValue": 200000.0}},
    }
    findings = lighthouse_json.map_lighthouse_json(doc, config=QualityDepthConfig())
    assert _by_rule(findings, "web_transfer_regression") == []


def test_no_regression_when_growth_below_pct_gate() -> None:
    """Growth above the byte floor but below the pct gate → no regression."""
    # 1_000_000 -> 1_020_000 = +2% (< 10%) but +20000 bytes (> 10240): pct gate
    # blocks it. (Use no budget breach concern — set a huge budget.)
    doc = {
        "categories": {"performance": {"score": 0.9}},
        "audits": {"total-byte-weight": {"numericValue": 1020000.0}},
    }
    cfg = QualityDepthConfig(web_budget_bytes=99_000_000)
    findings = lighthouse_json.map_lighthouse_json(
        doc, config=cfg, prior_web_bytes=1_000_000
    )
    assert _by_rule(findings, "web_transfer_regression") == []


def test_no_regression_when_growth_below_floor_gate() -> None:
    """Growth above the pct gate but below the byte floor → no regression."""
    # 1000 -> 1200 = +20% (> 10%) but +200 bytes (< 10240): floor blocks it.
    doc = {
        "categories": {"performance": {"score": 0.9}},
        "audits": {"total-byte-weight": {"numericValue": 1200.0}},
    }
    findings = lighthouse_json.map_lighthouse_json(
        doc, config=QualityDepthConfig(), prior_web_bytes=1000
    )
    assert _by_rule(findings, "web_transfer_regression") == []


def test_oversized_and_regression_independent(load_json) -> None:
    """A doc above budget AND with a qualifying prior emits BOTH (independent)."""
    doc = load_json("lighthouse_lhr.json")  # 3 MB > budget
    findings = lighthouse_json.map_lighthouse_json(
        doc, config=QualityDepthConfig(), prior_web_bytes=100000
    )
    assert len(_by_rule(findings, "web_transfer_oversized")) == 1
    assert len(_by_rule(findings, "web_transfer_regression")) == 1
    assert len(_by_rule(findings, "lighthouse_perf_summary")) == 1


def test_all_findings_runtime_candidate_capped_at_major(load_json) -> None:
    """Every perf finding is runtime/candidate and severity <= major."""
    doc = load_json("lighthouse_lhr.json")
    findings = lighthouse_json.map_lighthouse_json(
        doc, config=QualityDepthConfig(), prior_web_bytes=100000
    )
    assert findings
    for f in findings:
        assert f.evidence_type == "runtime"
        assert f.confidence == "candidate"
        assert f.severity in {"info", "minor", "major"}


def test_all_recommendations_self_enforce_verify_phrasing(load_json) -> None:
    """Every recommendation says 'verify' and carries no enforced/secure/protected."""
    doc = load_json("lighthouse_lhr.json")
    findings = lighthouse_json.map_lighthouse_json(
        doc, config=QualityDepthConfig(), prior_web_bytes=100000
    )
    for f in findings:
        assert "verify" in f.recommendation.lower()
        assert _BANNED.search(f.recommendation) is None


def test_map_lighthouse_lhr_alias_matches(load_json) -> None:
    """The scaffold-facing map_lighthouse_lhr alias delegates to map_lighthouse_json."""
    doc = load_json("lighthouse_lhr.json")
    via_alias = lighthouse_json.map_lighthouse_lhr(doc)
    via_main = lighthouse_json.map_lighthouse_json(doc, config=QualityDepthConfig())
    assert [f.rule_id for f in via_alias] == [f.rule_id for f in via_main]
