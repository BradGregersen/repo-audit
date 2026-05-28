"""01-REVIEW Finding #1 regression — paths.py collision must be symmetric on .md + .json."""
from datetime import date

from repo_audit.meta.paths import state_report_paths


def test_collision_when_only_json_exists(tmp_path):
    """If only the .json sibling exists, next call MUST return -2 paths."""
    repo = tmp_path / "regression-repo"
    repo.mkdir()
    out = repo / "docs" / "state-reports"
    out.mkdir(parents=True)
    slug_date = date(2026, 5, 28)
    # Pre-create only the .json
    (out / "regression-repo-state-report-2026-05-28.json").write_text("{}", encoding="utf-8")
    md, js = state_report_paths(repo, slug_date)
    assert md.name.endswith("-2.md")
    assert js.name.endswith("-2.json")


def test_collision_inside_loop_when_intermediate_json_exists(tmp_path):
    """If -2.md is free but -2.json exists (asymmetric leftover), MUST advance to -3."""
    repo = tmp_path / "regression-repo"
    repo.mkdir()
    out = repo / "docs" / "state-reports"
    out.mkdir(parents=True)
    slug_date = date(2026, 5, 28)
    (out / "regression-repo-state-report-2026-05-28.md").write_text("# x", encoding="utf-8")
    (out / "regression-repo-state-report-2026-05-28.json").write_text("{}", encoding="utf-8")
    (out / "regression-repo-state-report-2026-05-28-2.json").write_text("{}", encoding="utf-8")
    md, js = state_report_paths(repo, slug_date)
    assert md.name.endswith("-3.md")
    assert js.name.endswith("-3.json")
