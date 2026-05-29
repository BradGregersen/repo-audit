"""Plan 05-03 Task 3 — the rendered Trends-vs-prior section (SC-1 / SC-3).

Both tests route through the real ``repo-audit scan`` CLI chokepoint (no template
bypass) so the assertion is end-to-end:

  * test_first_scan_baseline — a fresh repo with no prior sidecar renders the
    baseline one-liner and NO "## Trends vs prior (" header (SC-3 / TREND-04 —
    no fake zero-deltas).
  * test_second_scan_deltas — a repo with a yesterday-dated sidecar renders the
    "## Trends vs prior (" header, a delta row, and the three labeled finding
    groups (SC-1 / SC-2 surfaced; D-05-06 three-group structure).

``--no-agent`` is passed so the deterministic render path is exercised without
a live Claude Code CLI; the Trends delta table renders regardless of the agent
(the agent only adds the narrative beneath it).
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from repo_audit.cli import app
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.report import ReportMeta, ScanReport


def _write_prior_sidecar(repo: Path, slug: str, scan_date: date) -> Path:
    """Write a valid prior JSON sidecar with a couple of findings to diff against."""
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    prior = ScanReport(
        schema_version="1",
        meta=ReportMeta(
            repo_slug=slug,
            commit_sha="DEADBEEF",
            scan_date=scan_date,
            tool_version="0.0.0",
        ),
        findings=[
            Finding(
                dimension="process",
                severity="info",
                evidence_type="static",
                confidence="high",
                source_tool="pygit2",
                source_collector="git_cadence",
                evidence=Evidence(tool="pygit2", parsed_value={"commits_total": 5}),
            ),
            # An eslint-shaped finding tied to a file that will be ABSENT in the
            # current scan repo -> classified vanished_with_file (file deleted),
            # exercising the D-05-06 "Vanished with file" group.
            Finding(
                dimension="quality",
                severity="major",
                file="src/gone.ts",
                line=10,
                evidence_type="static",
                confidence="high",
                source_tool="eslint",
                source_collector="typescript_adapter",
                rule_id="no-unused-vars",
                evidence=Evidence(tool="eslint", parsed_value={"rule_id": "no-unused-vars"}),
            ),
        ],
    )
    path = out_dir / f"{slug}-state-report-{scan_date.isoformat()}.json"
    path.write_text(prior.model_dump_json(), encoding="utf-8")
    return path


def test_first_scan_baseline(runner, fake_repo):
    """SC-3 / TREND-04 — first scan renders the baseline one-liner, no delta table."""
    slug = "trend-baseline-repo"
    repo = fake_repo({"README.md": "# x\n"}, name=slug)
    result = runner.invoke(app, ["scan", str(repo), "--no-agent"])
    assert result.exit_code == 0

    md_files = list((repo / "docs" / "state-reports").glob(f"{slug}-state-report-*.md"))
    assert len(md_files) == 1
    md = md_files[0].read_text(encoding="utf-8")

    assert "baseline run — no prior report to diff against" in md
    # No delta-table header on a baseline run (no fake zeros).
    assert "## Trends vs prior (" not in md


def test_second_scan_deltas(runner, fake_repo):
    """SC-1 / SC-2 — second scan renders the Trends section + 3 labeled groups."""
    slug = "trend-delta-repo"
    repo = fake_repo({"README.md": "# x\n"}, name=slug)
    _write_prior_sidecar(repo, slug, date.today() - timedelta(days=1))

    result = runner.invoke(app, ["scan", str(repo), "--no-agent"])
    assert result.exit_code == 0

    md_files = list((repo / "docs" / "state-reports").glob(f"{slug}-state-report-*.md"))
    assert len(md_files) == 1
    md = md_files[0].read_text(encoding="utf-8")

    # The dedicated Trends header (with the prior baseline date in parens).
    assert "## Trends vs prior (" in md
    # A delta table row (the Commits metric row is always present).
    assert "| Commits |" in md
    # The three explicitly-labeled finding groups (D-05-06).
    assert "### Resolved" in md
    assert "### Vanished with file" in md
    assert "### Still present" in md
    # The anti-cheating caveat copy is present.
    assert "NOT counted as a fix" in md
    # The prior eslint finding's file is gone from the current repo -> it must be
    # classified as vanished_with_file, surfacing under that group.
    assert "src/gone.ts" in md
