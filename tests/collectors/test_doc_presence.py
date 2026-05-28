"""COLL-04 doc_presence tests (Plan 02-05).

Strict from this plan forward: doc_presence emits a Finding per target
(README, LICENSE, CHANGELOG, docs/) regardless of presence; SAFE-03
ceiling structurally enforced via parsed_value['presence_only']=True;
British 'LICENCE' spelling tolerated; source_tool is 'in-process'.
"""


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


def test_doc_presence_emits_finding_for_each_target_when_absent(fake_repo):
    from repo_audit.collectors.doc_presence import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"src.py": "x=1\n"}, name="bare-repo")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    # 4 findings always: README + LICENSE + CHANGELOG + docs/
    assert len(result.findings) == 4
    labels = {f.evidence.parsed_value["doc"] for f in result.findings}
    assert labels == {"README", "LICENSE", "CHANGELOG", "docs/"}
    # All present=False
    for f in result.findings:
        assert f.evidence.parsed_value["present"] is False
        assert f.recommendation.startswith("add ")


def test_doc_presence_tolerates_british_licence_spelling(fake_repo):
    from repo_audit.collectors.doc_presence import run
    from repo_audit.walker import build_repo_index
    repo = fake_repo({"LICENCE.md": "MIT\n"}, name="british")
    wr = build_repo_index(repo)
    result = run(repo, wr.index)
    license_finding = next(
        f for f in result.findings
        if f.evidence.parsed_value["doc"] == "LICENSE"
    )
    assert license_finding.evidence.parsed_value["present"] is True
