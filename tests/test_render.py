"""Renderer skeleton tests. Implementation lands in Plan 04 (Wave 2)."""
import json
from datetime import date


ALL_SECTION_HEADINGS = [
    "## 1. Executive summary",
    "## 2. Scope ledger",
    "## 3. Security & SAST",
    "## 4. Architecture rot",
    "## 5. Test integrity",
    "## 6. Correctness & data/privacy",
    "## 7. Quality / perf / footprint / docs",
    "## 8. Process & backlog",
    "## 9. Observability & runtime",
]


def _empty_scan_report():
    from repo_audit.schema.report import ScanReport, ReportMeta
    return ScanReport(
        schema_version="1",
        meta=ReportMeta(
            repo_slug="test-repo",
            commit_sha="0" * 40,
            scan_date=date(2026, 5, 28),
            tool_version="0.1.0",
            detected_stacks=[],
            baseline_run=True,
        ),
        findings=[],
    )


def test_seven_dimensions_in_order():
    """SC-3 / REP-01 — rendered markdown contains all 7 dimensions + ExecSummary + ScopeLedger in fixed order."""
    from repo_audit.render.renderer import render_markdown
    md = render_markdown(_empty_scan_report())
    prev = -1
    for heading in ALL_SECTION_HEADINGS:
        idx = md.find(heading)
        assert idx > prev, f"heading {heading!r} missing or out of order"
        prev = idx


def test_pending_markers_present_for_each_dimension():
    """D-09 / SAFE-08 — each dimension has explicit pending marker (no silent empty)."""
    from repo_audit.render.renderer import render_markdown
    md = render_markdown(_empty_scan_report())
    assert md.count("_(no collectors invoked for this dimension yet") >= 7


def test_executive_summary_pending_marker():
    """D-10 / D-70 — Executive Summary present with the deterministic header.

    Plan 04-08 replaced the Phase-1 placeholder line
    ('_(no blocker/critical findings — no collectors invoked yet)_') with the
    D-70 authoritative count header, which is built from the structurally-
    counted finding store. With an empty store it reports the all-zero header.
    """
    from repo_audit.render.renderer import render_markdown
    md = render_markdown(_empty_scan_report())
    assert "**0 blocker, 0 critical finding(s)** across 0 dimension(s)." in md


def test_scope_ledger_pending_marker():
    """D-11 / D-30 — Scope Ledger present with three subsections.

    Plan 02-06 replaced the Phase 1 single-line placeholder with the
    Scanned/Skipped/Unavailable three-table layout (D-30). On an empty
    ScanReport the empty-marker phrases under each subsection are the
    new structural pending markers.
    """
    from repo_audit.render.renderer import render_markdown
    md = render_markdown(_empty_scan_report())
    assert "### Scanned" in md
    assert "### Skipped" in md
    assert "### Unavailable" in md
    assert "_(no directories scanned)_" in md
    assert "_(no directories skipped)_" in md
    # "full scan" is the empty-unavailable-set sentinel
    assert "_(no unavailable dimensions — full scan)_" in md


def test_header_has_repo_slug_commit_sha_date_version(runner, fake_repo):
    """D-12 — header includes repo name, commit SHA, scan date, tool version, baseline marker."""
    from repo_audit.cli import app
    repo = fake_repo({"README.md": "# x\n"}, name="hdr-test")
    result = runner.invoke(app, ["scan", str(repo)])
    md = next((repo / "docs" / "state-reports").glob("*.md")).read_text()
    assert "hdr-test" in md
    assert "baseline run" in md.lower()


def test_scan_writes_report_and_sidecar(runner, fake_repo):
    """SC-3 / SCH-06 — both .md and .json land in docs/state-reports/ with schema_version="1"."""
    from repo_audit.cli import app
    repo = fake_repo({"README.md": "# x\n"}, name="sc3-repo")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0
    json_file = next((repo / "docs" / "state-reports").glob("*.json"))
    sidecar = json.loads(json_file.read_text())
    assert sidecar["schema_version"] == "1"


def test_read_only_contract(runner, fake_repo):
    """REP-03 — `repo-audit scan` writes ONLY .md + .json in docs/state-reports/; no other mutations."""
    import subprocess
    from repo_audit.cli import app
    repo = fake_repo({"README.md": "# x\n"}, name="read-only-test")
    runner.invoke(app, ["scan", str(repo)])
    # git status --porcelain in the target repo: every modified path must be under docs/state-reports/.
    # ``--untracked-files=all`` (-uall) expands new directories to their actual file
    # entries -- without it, git collapses the new ``docs/`` tree to a single
    # ``?? docs/`` line and the REP-03 contract can't be verified at file granularity.
    out = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain", "-uall"],
        capture_output=True, text=True, check=True,
    )
    lines = [line for line in out.stdout.splitlines() if line.strip()]
    assert lines, "expected `repo-audit scan` to leave at least one new file in the target repo"
    for line in lines:
        path = line[3:].strip()
        assert path.startswith("docs/state-reports/"), f"unexpected mutation: {path}"


def test_observability_caveat():
    """SAFE-02 / D-18 — renderer's observability-dimension path requires runtime-not-verified caveat."""
    # Implementation lands in Plan 04; this stub pins the test name.
    from repo_audit.render.renderer import render_markdown
    md = render_markdown(_empty_scan_report())
    # Phase 1: section exists with pending marker (no findings yet to trigger caveat logic).
    # Plan 04 will extend this test once a sample observability finding can be constructed.
    assert "## 9. Observability & runtime" in md
