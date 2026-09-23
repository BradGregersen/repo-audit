"""End-to-end regression guard for completion-honesty on partial scans.

The bug: `repo-audit scan --no-agent
companion-app` exited 3 (completion-honesty) on a PARTIAL scan because a benign
totality substring ("all") appeared in untrusted collector-derived DATA (a
secret finding's rule_id / file path, the security dimension finding table)
rather than in a totality CLAIM in the report's own narrative.

The fix lives in the render chokepoint: `render_and_write` lints ONLY the
HONESTY:START/END-marked CLAIM prose (via
`completion_honesty.extract_claim_spans`), never the structured finding tables /
scope-ledger rows / JSON sidecar field values (D-051-11). The unit-level scoping
is pinned by tests/collectors/test_completion_honesty.py; THIS module pins the
end-to-end contract through the real `render_and_write` pipeline so the Blocker-B
acceptance check can never silently regress:

  1. A PARTIAL report whose only totality token is inside a secret finding's
     rule_id / file path renders and WRITES (exit 0) — DATA does not hard-refuse.
  2. The redacted secret row survives in the markdown (data not dropped).
  3. The honesty guarantee is intact: a genuine totality CLAIM in the marked
     narrative still refuses (exit 3) — proving the scoping did not gut the guard.
"""
from __future__ import annotations

from datetime import date

import pytest

from repo_audit.render.completion_honesty import (
    CompletionHonestyViolation,
    completion_honesty_lint,
    extract_claim_spans,
)
from repo_audit.render.renderer import render_and_write
from repo_audit.schema import ReportMeta, ScanReport, ScopeLedger
from repo_audit.schema.finding import Evidence, Finding


def _secret_finding(rule_id: str, file: str) -> Finding:
    """A security finding shaped like secret_detection's redacted output."""
    return Finding(
        dimension="security",
        severity="major",
        confidence="candidate",
        evidence_type="heuristic",
        source_tool="in-process",
        source_collector="secret_detection",
        file=file,
        line=3,
        rule_id=rule_id,
        evidence=Evidence(
            tool="in-process",
            output_snippet=f"{rule_id} [REDACTED:32] at line 3",
            parsed_value={"rule_id": rule_id, "redacted_len": 32},
            line_range=(3, 3),
        ),
    )


def _partial_report(findings: list[Finding]) -> ScanReport:
    meta = ReportMeta(
        repo_slug="companion-app",
        commit_sha="0" * 40,
        scan_date=date(2026, 5, 30),
        tool_version="0.1.0",
        partial=True,  # the condition under which the matcher is active
    )
    return ScanReport(
        schema_version="1", meta=meta, findings=findings, scope_ledger=ScopeLedger()
    )


def test_partial_benign_all_in_secret_data_writes(tmp_path):
    """Blocker B: benign 'all' in a secret rule_id / path → exit 0, files written."""
    sr = _partial_report([_secret_finding("all", "src/all/config.kt")])
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    rc = render_and_write(sr, md, js)
    assert rc == 0, "partial report must not be refused for a benign 'all' in DATA"
    assert md.exists() and js.exists()


def test_partial_secret_data_row_still_rendered(tmp_path):
    """The redacted finding row survives in the markdown (data moved, not dropped)."""
    sr = _partial_report([_secret_finding("all", "src/all/config.kt")])
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    rc = render_and_write(sr, md, js)
    assert rc == 0
    assert "[REDACTED:32]" in md.read_text(encoding="utf-8")


def test_partial_genuine_narrative_totality_still_refuses():
    """Honesty guarantee intact: a totality CLAIM in marked narrative still refuses.

    Drives the matcher exactly as the renderer does — extract the HONESTY-marked
    claim spans, then lint them. A totality token there is a genuine overclaim on
    a partial scan and must raise (-> CLI exit 3).
    """
    buf = (
        "## 1. Executive summary\n"
        "<!--HONESTY:START-->\n"
        "Every dimension was scanned and the audit is complete.\n"
        "<!--HONESTY:END-->\n"
    )
    claims = extract_claim_spans(buf)
    with pytest.raises(CompletionHonestyViolation):
        completion_honesty_lint(claims, partial=True, buffer_name="markdown")
