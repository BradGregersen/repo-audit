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


def test_file_over_max_bytes_never_line_counted(fake_repo, monkeypatch):
    """SCAN-BOUND-01: a file > MAX_FILE_BYTES is skipped before _count_lines.

    The load-bearing 999.1 fix — RESEARCH measured _count_lines streaming
    14.18 GB of binary .apk/.mp4 artifacts for 337s. A >1MB file is
    generated/binary, never a source file we'd flag for line length, so it
    is skipped BEFORE any content read. We build a synthetic repo_index
    (not the walker) so we can hand it an oversized FileMeta without writing
    a multi-MB fixture, and we spy on _count_lines to prove it is never
    invoked for the large file while the normal over-cap file still emits.
    """
    from repo_audit.collectors import file_size_cap as fsc
    from repo_audit.walker.repo_index import FileMeta

    repo = fake_repo({}, name="byte-ceiling")
    # A real over-cap .py source file (350 lines, ~50 bytes/line ≈ 17.5 KB).
    long_line = "result = func_call(arg1, arg2, arg3, arg4)  # ok\n"
    normal = repo / "big.py"
    normal.write_text(long_line * 350, encoding="utf-8")
    # An oversized FileMeta whose backing file we do NOT create at >1MB —
    # the guard reads meta.size_bytes, not the disk, so a claimed size of
    # 5 MB is enough to exercise the ceiling without a giant fixture.
    huge = repo / "blob.apk"
    huge.write_text("x\n" * 5, encoding="utf-8")  # tiny on disk
    index = {
        normal: FileMeta(path=normal, size_bytes=normal.stat().st_size, ext=".py"),
        huge: FileMeta(path=huge, size_bytes=5_000_000, ext=".apk"),  # claimed 5MB
    }

    counted: list = []
    real = fsc._count_lines

    def spy(p):
        counted.append(p)
        return real(p)

    monkeypatch.setattr(fsc, "_count_lines", spy)
    result = fsc.run(repo, index)

    # The >1MB file is never line-counted (skipped before _count_lines).
    assert huge not in counted, "blob.apk (5MB) must be skipped before _count_lines"
    # And produces no Finding.
    assert all(
        f.evidence.parsed_value.get("file") != "blob.apk"
        for f in result.findings
    )
    # The normal over-cap source file still emits a Finding.
    assert any(
        f.evidence.parsed_value.get("file") == "big.py"
        for f in result.findings
    )


def test_max_file_bytes_constant_matches_secret_detection():
    """MAX_FILE_BYTES mirrors secret_detection.MAX_FILE_BYTES (D-051 precedent)."""
    from repo_audit.collectors.file_size_cap import MAX_FILE_BYTES
    from repo_audit.collectors.secret_detection import (
        MAX_FILE_BYTES as SECRET_MAX,
    )
    assert MAX_FILE_BYTES == 1_000_000
    assert MAX_FILE_BYTES == SECRET_MAX


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
