"""COLL-06 file_size_cap tests (Plan 02-05).

Strict from this plan forward: DEFAULT_SIZE_CAPS pinned to D-36 values;
get_threshold seam present (Phase 7 YAML overlay swaps it); coarse
byte pre-filter avoids reading small files; over-cap files emit
severity='minor' Findings with line_count/threshold/overage parsed_value.
"""


def test_default_caps_match_d36(fake_repo):
    from repo_audit.collectors.file_size_cap import (
        DEFAULT_SIZE_CAPS, get_threshold,
    )
    assert DEFAULT_SIZE_CAPS[".tsx"] == 200
    assert DEFAULT_SIZE_CAPS[".ts"] == 300
    assert DEFAULT_SIZE_CAPS[".js"] == 300
    assert DEFAULT_SIZE_CAPS[".py"] == 300
    assert DEFAULT_SIZE_CAPS[".kt"] == 300
    assert get_threshold(".unknown_ext") == 300  # default


def test_file_over_cap_emits_finding(fake_repo):
    from repo_audit.collectors.file_size_cap import run
    from repo_audit.walker import build_repo_index
    # Realistic line bytes (~50 chars/line) so the coarse byte pre-filter
    # (size_bytes < threshold * BYTES_PER_LINE_FLOOR = 12000 for .py) does
    # NOT skip the file. 350 lines * ~50 bytes = ~17500 bytes > 12000.
    long_line = "result = func_call(arg1, arg2, arg3, arg4)  # ok\n"  # 50 bytes
    content = long_line * 350     # 350 lines, .py threshold=300
    repo = fake_repo({"big.py": content}, name="over-cap")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert any(
        f.evidence.parsed_value.get("overage") == 50
        for f in result.findings
    )


def test_file_under_cap_no_finding(fake_repo):
    from repo_audit.collectors.file_size_cap import run
    from repo_audit.walker import build_repo_index
    content = "x=1\n" * 200     # 200 lines, .py threshold=300
    repo = fake_repo({"small.py": content}, name="under-cap")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert all(
        f.evidence.parsed_value.get("file") != "small.py"
        for f in result.findings
    )


def test_file_size_cap_tsx_uses_200_threshold(fake_repo):
    from repo_audit.collectors.file_size_cap import run
    from repo_audit.walker import build_repo_index
    # 250 .tsx lines: under 300 (default) but over 200 (.tsx cap).
    # Lines must be >= 40 bytes each so the coarse byte pre-filter
    # (size_bytes < 200 * 40 = 8000 for .tsx) does NOT skip the file.
    # 250 lines * 50 bytes = 12500 > 8000.
    long_line = "const result = someFunction(arg1, arg2, arg3);\n"  # 47 bytes
    content = long_line * 250
    repo = fake_repo({"big.tsx": content}, name="tsx-cap")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    tsx_findings = [f for f in result.findings if f.file == "big.tsx"]
    assert len(tsx_findings) == 1
    assert tsx_findings[0].evidence.parsed_value["threshold"] == 200


def test_file_size_cap_coarse_filter_skips_small_files_efficiently(
    fake_repo, monkeypatch,
):
    """Pattern 6: files where size_bytes < threshold*40 must NOT be opened for line-counting."""
    from repo_audit.collectors import file_size_cap as fsc
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"small.py": "x=1\n"}, name="small")
    wr = build_repo_index(repo)
    # Track _count_lines invocations
    calls = {"count": 0}
    real = fsc._count_lines

    def spy(p):
        calls["count"] += 1
        return real(p)

    monkeypatch.setattr(fsc, "_count_lines", spy)
    fsc.run(repo, wr.index)
    # small.py is 4 bytes; threshold=.py=300; 300*40=12000; 4 < 12000 -> skip
    assert calls["count"] == 0
