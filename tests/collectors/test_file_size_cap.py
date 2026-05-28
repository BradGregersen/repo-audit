"""COLL-06 tests. STUB — implementation lands in Plan 02-05."""
import pytest
pytestmark = pytest.mark.xfail(strict=False, reason="Plan 02-05 implements file_size_cap")


def test_default_caps_match_d36(fake_repo):
    from repo_audit.collectors.file_size_cap import DEFAULT_SIZE_CAPS, get_threshold
    assert DEFAULT_SIZE_CAPS[".tsx"] == 200
    assert DEFAULT_SIZE_CAPS[".ts"] == 300
    assert DEFAULT_SIZE_CAPS[".js"] == 300
    assert DEFAULT_SIZE_CAPS[".py"] == 300
    assert DEFAULT_SIZE_CAPS[".kt"] == 300
    assert get_threshold(".unknown_ext") == 300  # default


def test_file_over_cap_emits_finding(fake_repo):
    from repo_audit.collectors.file_size_cap import run
    from repo_audit.walker import build_repo_index
    content = "x=1\n" * 350     # 350 lines, .py threshold=300
    repo = fake_repo({"big.py": content}, name="over-cap")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert any(f.evidence.parsed_value.get("overage") == 50 for f in result.findings)


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
