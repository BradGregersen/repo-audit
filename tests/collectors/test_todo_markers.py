"""COLL-05 todo_markers tests (Plan 02-05).

Strict from this plan forward: \\b(TODO|FIXME|HACK|XXX)\\b case-insensitive
across text files in RepoIndex; \\bTODOed\\b must NOT match; line number
recorded (1-indexed); binary/non-text extensions skipped.
"""


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


def test_todo_markers_case_insensitive(fake_repo):
    from repo_audit.collectors.todo_markers import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo(
        {"a.py": "# todo: lower\n# FIXME: upper\n# Hack: mixed\n"},
        name="case",
    )
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    markers = {f.evidence.parsed_value["marker"] for f in result.findings}
    assert markers == {"TODO", "FIXME", "HACK"}


def test_todo_markers_skips_non_text_files(fake_repo):
    """Binary-extension (.png) files must NOT be opened for TODO grep."""
    from repo_audit.collectors.todo_markers import run
    from repo_audit.walker import build_repo_index, FileMeta
    repo = fake_repo({}, name="binary-skip")
    img = repo / "img.png"
    img.write_bytes(b"PNG TODO inside binary data\n")
    # Hand-craft an index entry the walker would have produced.
    index = {img: FileMeta(path=img, size_bytes=img.stat().st_size, ext=".png")}
    result = run(repo, index)
    assert len(result.findings) == 0
