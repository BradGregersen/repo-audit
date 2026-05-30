"""Walker (RepoIndex + skip-dirs) tests. STRICT — lands in Plan 02-01a."""
from pathlib import Path

from repo_audit.walker import build_repo_index, DEFAULT_SKIP_DIRS


def test_walker_indexes_repo_files(tmp_path):
    repo = tmp_path / "small"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "b.md").write_text("# x\n", encoding="utf-8")
    result = build_repo_index(repo)
    assert result.status == "ok"
    paths = {p.name for p in result.index}
    assert paths == {"a.py", "b.md"}


def test_walker_records_filemeta(tmp_path):
    repo = tmp_path / "meta"
    repo.mkdir()
    f = repo / "x.ts"
    content = "export const x = 1;\n"
    f.write_text(content, encoding="utf-8")
    result = build_repo_index(repo)
    meta = next(iter(result.index.values()))
    assert meta.size_bytes == len(content.encode("utf-8"))
    assert meta.ext == ".ts"
    assert meta.path == f.resolve() or meta.path == f


def test_walker_skips_default_dirs_auto_logged(skipped_dir_repo):
    result = build_repo_index(skipped_dir_repo)
    # node_modules contents NOT in index
    assert all("node_modules" not in str(p) for p in result.index)
    # skipped_dirs auto-logged with reason='dependencies'
    reasons = {reason for _, reason in result.skipped_dirs}
    assert "dependencies" in reasons


def test_walker_does_not_follow_symlinks(tmp_path):
    repo = tmp_path / "sym"
    repo.mkdir()
    (repo / "real.txt").write_text("x\n", encoding="utf-8")
    # Cyclic symlink: link → repo itself
    try:
        (repo / "loop").symlink_to(repo)
    except OSError:
        import pytest
        pytest.skip("symlink creation not supported on this filesystem")
    result = build_repo_index(repo)
    # real.txt should be indexed; no recursion through loop
    assert any(p.name == "real.txt" for p in result.index)
    # status should be 'ok' (not partial — far below 200k cap)
    assert result.status == "ok"


def test_walker_excludes_docs_state_reports(tmp_path):
    """Pitfall 7: docs/state-reports/ is the tool's own output; excluded from index."""
    repo = tmp_path / "self-output"
    repo.mkdir()
    sr = repo / "docs" / "state-reports"
    sr.mkdir(parents=True)
    (sr / "yesterday.md").write_text("# old\n", encoding="utf-8")
    (repo / "src.py").write_text("x = 1\n", encoding="utf-8")
    result = build_repo_index(repo)
    # yesterday.md NOT in index
    assert all("state-reports" not in str(p) for p in result.index)
    # src.py IS in index
    assert any(p.name == "src.py" for p in result.index)


def test_walker_skipped_dirs_use_only_locked_reason_literals():
    """SkipReason Literal — only the locked values allowed.

    SCAN-BOUND-01 added an additive 7th member 'budget-truncated' (used by
    the walker caps, NOT by DEFAULT_SKIP_DIRS). DEFAULT_SKIP_DIRS itself
    still only uses the original six dir-classification reasons.
    """
    from repo_audit.walker.skip_dirs import DEFAULT_SKIP_DIRS
    allowed = {"vcs", "dependencies", "build-artifact", "cache", "editor", "test-output"}
    used = set(DEFAULT_SKIP_DIRS.values())
    assert used.issubset(allowed), f"unexpected SkipReason value: {used - allowed}"


def test_skipreason_includes_budget_truncated_additively():
    """SCAN-BOUND-01: 'budget-truncated' is a valid SkipReason; six originals kept."""
    import typing

    from repo_audit.walker.skip_dirs import SkipReason

    members = set(typing.get_args(SkipReason))
    assert "budget-truncated" in members
    assert {
        "vcs", "dependencies", "build-artifact", "cache", "editor", "test-output",
    }.issubset(members)


def test_walker_oversized_file_is_skipped_not_indexed(tmp_path, monkeypatch):
    """SCAN-COVER-01 / T-0511-02: a single file over MAX_FILE_INDEX_BYTES is
    skipped (not indexed, not counted) but the walk continues.

    Uses a small monkeypatched per-file ceiling so the test stays fast. The
    small sibling file MUST still be indexed; the oversized file MUST NOT.
    """
    from repo_audit.walker import repo_index as ri

    repo = tmp_path / "oversized"
    repo.mkdir()
    (repo / "small.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "big.bin").write_text("x" * 5000, encoding="utf-8")
    monkeypatch.setattr(ri, "MAX_FILE_INDEX_BYTES", 1000)

    result = ri.build_repo_index(repo)

    names = {p.name for p in result.index}
    assert "small.py" in names
    assert "big.bin" not in names
    assert result.status == "partial"
    # The oversized file's path is disclosed in a budget-truncated row.
    truncated = [p for p, r in result.skipped_dirs if r == "budget-truncated"]
    assert any(p.name == "big.bin" for p in truncated)
    assert result.notes  # non-empty


def test_walker_subtree_byte_cap_prunes_one_subtree_keeps_siblings(
    tmp_path, monkeypatch,
):
    """SCAN-COVER-01 / T-0511-03: one subtree over SUBTREE_BYTE_CAP is pruned
    and recorded, but a sibling top-level subtree is STILL indexed.

    This is the core coverage fix: a big subtree must not knock out siblings.
    """
    from repo_audit.walker import repo_index as ri

    repo = tmp_path / "subtree-cap"
    repo.mkdir()
    big = repo / "big"
    big.mkdir()
    # Several files summing well over the (monkeypatched-low) subtree cap.
    for i in range(3):
        (big / f"b{i}.py").write_text("x" * 1000, encoding="utf-8")
    small = repo / "small"
    small.mkdir()
    (small / "keep.py").write_text("y = 2\n", encoding="utf-8")
    monkeypatch.setattr(ri, "SUBTREE_BYTE_CAP", 1500)

    result = ri.build_repo_index(repo)

    names = {p.name for p in result.index}
    # The sibling subtree's file survives — this is the bug being fixed.
    assert "keep.py" in names
    assert result.status == "partial"
    # A dir under big/ is recorded as budget-truncated.
    truncated = [p for p, r in result.skipped_dirs if r == "budget-truncated"]
    assert any("big" in p.parts for p in truncated)


def test_walker_root_level_file_counted_under_root_sentinel(
    tmp_path, monkeypatch,
):
    """SCAN-COVER-01 / B2: files directly in repo_path are bucketed under the
    '<root>' sentinel subtree key and bounded by SUBTREE_BYTE_CAP — no
    IndexError on empty rel.parts.
    """
    from repo_audit.walker import repo_index as ri

    repo = tmp_path / "root-files"
    repo.mkdir()
    # Three root-level files (1000 bytes each) with a 1500-byte cap. The "<root>"
    # bucket accumulates AFTER each index: a -> 1000 (kept), b -> 2000 (kept, but
    # tips the bucket over the cap so "<root>" is pruned), c -> dropped. At least
    # one root file must be dropped once the "<root>" bucket overflows.
    for name in ("a.py", "b.py", "c.py"):
        (repo / name).write_text("x" * 1000, encoding="utf-8")
    monkeypatch.setattr(ri, "SUBTREE_BYTE_CAP", 1500)

    # Must not raise IndexError on empty rel.parts (the "<root>" sentinel path).
    result = ri.build_repo_index(repo)

    assert result.status == "partial"
    truncated = [r for _, r in result.skipped_dirs if r == "budget-truncated"]
    assert truncated  # the root subtree overflow is disclosed
    # At least one root file is dropped once the "<root>" bucket exceeds the cap.
    indexed_root = {p.name for p in result.index} & {"a.py", "b.py", "c.py"}
    assert len(indexed_root) < 3


def test_walker_depth_cap_prunes_and_records_budget_truncated(
    tmp_path, monkeypatch,
):
    """SCAN-BOUND-01 / T-051-02: traversal deeper than MAX_DEPTH is pruned."""
    from repo_audit.walker import repo_index as ri

    repo = tmp_path / "deep"
    repo.mkdir()
    # Build a chain repo/d0/d1/d2/d3 with a file at the deepest level.
    cur = repo
    for i in range(4):
        cur = cur / f"d{i}"
        cur.mkdir()
    (cur / "deep.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(ri, "MAX_DEPTH", 2)

    result = ri.build_repo_index(repo)

    assert any(reason == "budget-truncated" for _, reason in result.skipped_dirs)
    # The deepest file beyond MAX_DEPTH must not be indexed.
    assert all("deep.py" not in str(p) for p in result.index)


def test_walker_healthy_tree_stays_ok_no_budget_truncated(tmp_path):
    """SCAN-BOUND-01: a small healthy tree under all caps stays status='ok'."""
    from repo_audit.walker import build_repo_index

    repo = tmp_path / "healthy"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "b.ts").write_text("export const b = 2;\n", encoding="utf-8")
    sub = repo / "src"
    sub.mkdir()
    (sub / "c.py").write_text("y = 2\n", encoding="utf-8")

    result = build_repo_index(repo)

    assert result.status == "ok"
    assert all(reason != "budget-truncated" for _, reason in result.skipped_dirs)


def test_run_collectors_past_deadline_marks_all_timeout(tmp_path):
    """SCAN-BOUND-01 / T-051-03: a deadline already in the past times out all.

    run_collectors with a past deadline marks EVERY collector status='timeout'
    deterministically and never raises (no mid-flight kill). The number of
    results equals the registry size so the ledger surfaces every collector.
    """
    import time

    from repo_audit.collectors import get_registry, run_collectors

    repo = tmp_path / "deadline"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")

    results = run_collectors(repo, {}, deadline=time.perf_counter() - 1)

    assert len(results) == len(get_registry())
    assert results, "registry must be non-empty"
    assert all(r.status == "timeout" for r in results)
    assert all(r.notes for r in results)


def test_run_collectors_default_deadline_none_runs_all(tmp_path):
    """SCAN-BOUND-01: deadline=None (default) preserves prior behaviour.

    With no deadline, every collector runs exactly as before — none is
    marked timeout by the budget path.
    """
    from repo_audit.collectors import get_registry, run_collectors

    repo = tmp_path / "no-deadline"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    from repo_audit.walker import build_repo_index

    wr = build_repo_index(repo)
    results = run_collectors(repo, wr.index)  # default deadline=None

    assert len(results) == len(get_registry())
    # No collector is timed out by the (absent) budget path. Individual
    # collectors may legitimately return other statuses (e.g. 'partial' when
    # gitleaks is absent), but none should be the budget-timeout sentinel.
    timeout_notes = [
        r for r in results
        if r.status == "timeout" and "time budget exceeded" in (r.notes or "")
    ]
    assert timeout_notes == []


def _build_capped_tree(root, big_name, small_name):
    """Helper: a repo with one over-cap subtree + one tiny subtree.

    Returns the repo path. Used by the order-independence test with
    order-forcing directory names (no os.walk mocking).
    """
    root.mkdir()
    big = root / big_name
    big.mkdir()
    for i in range(3):
        (big / f"b{i}.py").write_text("x" * 1000, encoding="utf-8")
    small = root / small_name
    small.mkdir()
    (small / "keep.py").write_text("y = 2\n", encoding="utf-8")
    return root


def test_byte_cap_is_order_independent(tmp_path, monkeypatch):
    """SCAN-COVER-01 / W2: the kept/pruned decision keys on the subtree, not on
    os.walk visitation order.

    Two REAL tmp trees with identical content but names that force DIFFERENT
    alphabetical (hence os.walk) order:
      * tree A: 'aaa' (over cap, visited FIRST) + 'zzz' (tiny, visited LAST)
      * tree B: 'zzz_big' (over cap, visited LAST) + 'aaa_small' (tiny, FIRST)
    In BOTH, the SMALL subtree's file is indexed and the BIG subtree is pruned.
    No os.walk mock — real on-disk ordering only.
    """
    from repo_audit.walker import repo_index as ri

    monkeypatch.setattr(ri, "SUBTREE_BYTE_CAP", 1500)

    tree_a = _build_capped_tree(tmp_path / "A", "aaa", "zzz")
    tree_b = _build_capped_tree(tmp_path / "B", "zzz_big", "aaa_small")

    res_a = ri.build_repo_index(tree_a)
    res_b = ri.build_repo_index(tree_b)

    # In both, the tiny sibling's file survives despite opposite walk order.
    assert "keep.py" in {p.name for p in res_a.index}
    assert "keep.py" in {p.name for p in res_b.index}
    # In both, the big subtree is pruned (budget-truncated) and status partial.
    assert res_a.status == "partial"
    assert res_b.status == "partial"
    big_a = [p for p, r in res_a.skipped_dirs if r == "budget-truncated"]
    big_b = [p for p, r in res_b.skipped_dirs if r == "budget-truncated"]
    assert any("aaa" in p.parts for p in big_a)
    assert any("zzz_big" in p.parts for p in big_b)

    # Additionally: walk one tree, then RENAME its dirs to flip alphabetical
    # order, and walk again — the indexed-file basename SET is identical.
    tree_c = _build_capped_tree(tmp_path / "C", "aaa", "zzz")
    before = {p.name for p in ri.build_repo_index(tree_c).index}
    (tree_c / "aaa").rename(tree_c / "zzz_renamed_big")
    (tree_c / "zzz").rename(tree_c / "aaa_renamed_small")
    after = {p.name for p in ri.build_repo_index(tree_c).index}
    assert before == after


def test_builds_releases_skipped(tmp_path):
    """SCAN-COVER-01 / W3: builds/ and releases/ are pruned as build-artifact
    (belt-and-suspenders) and disclosed in skipped_dirs; src/ is indexed.
    """
    from repo_audit.walker import build_repo_index

    repo = tmp_path / "artifacts"
    repo.mkdir()
    for d in ("builds", "releases"):
        sub = repo / d
        sub.mkdir()
        (sub / "artifact.bin").write_text("x" * 100, encoding="utf-8")
    src = repo / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")

    result = build_repo_index(repo)

    names = {p.name for p in result.index}
    assert "app.py" in names
    assert "artifact.bin" not in names
    reasons_by_name = {
        p.name: r for p, r in result.skipped_dirs
    }
    assert reasons_by_name.get("builds") == "build-artifact"
    assert reasons_by_name.get("releases") == "build-artifact"
