"""COLL-01 tests. STUB — implementation lands in Plan 02-02."""
import pytest
pytestmark = pytest.mark.xfail(strict=False, reason="Plan 02-02 implements git_cadence")


def test_cadence_counts_commits_and_authors(fake_repo_with_commits):
    from repo_audit.collectors.git_cadence import run
    repo = fake_repo_with_commits(
        n_commits=3,
        authors=["a@x.com", "a@x.com", "b@x.com"],
        days_ago_list=[0, 5, 35],
        name="cadence-3",
    )
    result = run(repo, {})
    assert result.status == "ok"
    assert len(result.findings) == 1
    pv = result.findings[0].evidence.parsed_value
    assert pv["commits_total"] == 3
    assert pv["contributor_count"] == 2
    assert pv["commits_by_window"]["7d"] == 1   # only days_ago=0 in 7d
    assert pv["commits_by_window"]["30d"] == 2  # days_ago 0 + 5


def test_cadence_on_non_git_path_returns_unavailable(tmp_path):
    from repo_audit.collectors.git_cadence import run
    result = run(tmp_path, {})
    assert result.status == "unavailable"


def test_cadence_finding_source_tool_pygit2(fake_repo_with_commits):
    from repo_audit.collectors.git_cadence import run
    repo = fake_repo_with_commits(n_commits=1, authors=["a@x.com"], name="src-tool")
    result = run(repo, {})
    if result.findings:
        assert result.findings[0].source_tool == "pygit2"
