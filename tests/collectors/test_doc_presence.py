"""COLL-04 tests. STUB — implementation lands in Plan 02-05."""
import pytest
pytestmark = pytest.mark.xfail(strict=False, reason="Plan 02-05 implements doc_presence")


def test_doc_presence_finds_all_four_targets(fake_repo):
    from repo_audit.collectors.doc_presence import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({
        "README.md": "# x\n", "LICENSE": "MIT\n", "CHANGELOG.md": "# v0\n",
        "docs/_keep.md": "kept\n",
    }, name="all-docs")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    assert result.status == "ok"
    labels = {f.evidence.parsed_value["doc"] for f in result.findings}
    assert labels == {"README", "LICENSE", "CHANGELOG", "docs/"}


def test_doc_presence_severity_capped_at_info(fake_repo):
    from repo_audit.collectors.doc_presence import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"x.py": "x=1\n"}, name="no-docs")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    for f in result.findings:
        assert f.severity == "info"  # SAFE-03 / D-19 ceiling
        assert f.evidence.parsed_value.get("presence_only") is True


def test_doc_presence_uses_in_process_source_tool(fake_repo):
    from repo_audit.collectors.doc_presence import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"README.md": "# x\n"}, name="src-tool")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    for f in result.findings:
        assert f.source_tool == "in-process"
