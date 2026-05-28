"""COLL-05 tests. STUB — implementation lands in Plan 02-05."""
import pytest
pytestmark = pytest.mark.xfail(strict=False, reason="Plan 02-05 implements todo_markers")


def test_todo_markers_finds_all_four_keywords(fake_repo):
    from repo_audit.collectors.todo_markers import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({
        "a.py": "# TODO: fix\n# FIXME: now\nx=1\n# HACK: temp\n# XXX: review\n",
    }, name="markers")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert result.status == "ok"
    assert len(result.findings) >= 4


def test_todo_markers_word_boundary(fake_repo):
    """\\bTODOed should NOT match \\bTODO\\b."""
    from repo_audit.collectors.todo_markers import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"a.py": "# TODOed yesterday\n"}, name="word-bound")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert len(result.findings) == 0


def test_todo_markers_records_line_number(fake_repo):
    from repo_audit.collectors.todo_markers import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"a.py": "x=1\n# TODO: y\n"}, name="line-no")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert any(f.line == 2 for f in result.findings)
