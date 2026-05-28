"""COLL-01 tests — implementation lands in Plan 02-02."""


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
    assert pv["commits_by_window"]["7d"] == 2   # days_ago 0 + 5 within 7d window
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


def test_cadence_includes_contributors_top5_sorted(fake_repo_with_commits):
    from repo_audit.collectors.git_cadence import run
    repo = fake_repo_with_commits(
        n_commits=5,
        authors=["alice@x.com", "alice@x.com", "alice@x.com", "bob@x.com", "carol@x.com"],
        days_ago_list=[0, 1, 2, 3, 4],
        name="top5",
    )
    result = run(repo, {})
    assert result.status == "ok"
    top5 = result.findings[0].evidence.parsed_value["contributors_top5"]
    # alice has 3 commits, leading
    assert top5[0][0] == "alice@x.com"
    assert top5[0][1] == 3


def test_cadence_partial_history_default_false(fake_repo_with_commits):
    from repo_audit.collectors.git_cadence import run
    repo = fake_repo_with_commits(n_commits=2, authors=["a@x.com", "b@x.com"], name="ph-default")
    result = run(repo, {})
    assert result.findings[0].evidence.parsed_value["partial_history"] is False


def test_cadence_project_age_days_zero_on_single_commit(fake_repo_with_commits):
    from repo_audit.collectors.git_cadence import run
    repo = fake_repo_with_commits(n_commits=1, authors=["a@x.com"], days_ago_list=[0], name="single")
    result = run(repo, {})
    assert result.findings[0].evidence.parsed_value["project_age_days"] == 0
