"""TREND-03 / SC-2 — three-way finding classification (guards RESEARCH Pitfall 2).

The SC-2 anti-cheating contract: deleting a file with findings MUST classify as
``vanished_with_file``, NEVER ``resolved``. A deletion is not a fix.

Classification rule (Pitfall 2):
    prior-ref absent from current AND file still present  → 'resolved'
    prior-ref absent from current AND file gone           → 'vanished_with_file'
    prior-ref present in current                          → 'still_present'
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.report import ReportMeta, ScanReport
from repo_audit.trend.delta import compute_trend, composite_finding_ref


def _eslint_finding(*, file: str, line: int, rule_id: str = "no-unused-vars") -> Finding:
    """An eslint-shaped finding at a known file:line (the cross-scan match key)."""
    return Finding(
        dimension="quality",
        severity="major",
        file=file,
        line=line,
        evidence_type="static",
        confidence="high",
        source_tool="eslint",
        source_collector="typescript_adapter",
        rule_id=rule_id,
        evidence=Evidence(tool="eslint", parsed_value={"rule_id": rule_id}),
    )


def _meta(scan_date: date, *, slug: str = "fake-repo") -> ReportMeta:
    return ReportMeta(
        repo_slug=slug,
        commit_sha="UNCOMMITTED",
        scan_date=scan_date,
        tool_version="0.0.0-test",
    )


def _report(findings: list[Finding], scan_date: date) -> ScanReport:
    return ScanReport(meta=_meta(scan_date), findings=findings)


def test_composite_finding_ref_matches_corroboration_scheme():
    """The shared match key is {source_tool}::{rule_id}::{file}:{line}."""
    f = _eslint_finding(file="src/a.ts", line=10, rule_id="no-unused-vars")
    assert composite_finding_ref(f) == "eslint::no-unused-vars::src/a.ts:10"


def test_finding_still_present_classifies_still_present(fake_repo):
    repo = fake_repo({"src/a.ts": "const x = 1;\n"})
    f = _eslint_finding(file="src/a.ts", line=10)
    prior = _report([f], date(2026, 5, 1))
    current = _report([_eslint_finding(file="src/a.ts", line=10)], date(2026, 5, 28))

    delta = compute_trend(prior, current, repo)

    matching = [c for c in delta.changes if c.finding_ref == composite_finding_ref(f)]
    assert len(matching) == 1
    assert matching[0].status == "still_present"


def test_finding_gone_with_file_present_classifies_resolved(fake_repo):
    """File A still exists on disk, finding gone → a genuine fix → resolved."""
    repo = fake_repo({"src/a.ts": "const x = 1;\n"})
    f = _eslint_finding(file="src/a.ts", line=10)
    prior = _report([f], date(2026, 5, 1))
    current = _report([], date(2026, 5, 28))  # finding is gone

    delta = compute_trend(prior, current, repo)

    matching = [c for c in delta.changes if c.finding_ref == composite_finding_ref(f)]
    assert len(matching) == 1
    assert matching[0].status == "resolved"


def test_finding_gone_with_file_deleted_classifies_vanished_with_file(fake_repo):
    """File A deleted from disk, finding gone → NOT a fix → vanished_with_file."""
    repo = fake_repo({"src/a.ts": "const x = 1;\n"})
    # Delete the file from disk so (repo / file).exists() is False.
    (Path(repo) / "src" / "a.ts").unlink()

    f = _eslint_finding(file="src/a.ts", line=10)
    prior = _report([f], date(2026, 5, 1))
    current = _report([], date(2026, 5, 28))

    delta = compute_trend(prior, current, repo)

    matching = [c for c in delta.changes if c.finding_ref == composite_finding_ref(f)]
    assert len(matching) == 1
    assert matching[0].status == "vanished_with_file"


def test_sc2_deleting_file_with_findings_is_never_resolved(fake_repo):
    """SC-2 ANTI-CHEATING: a deleted file with N findings → N vanished_with_file, 0 resolved.

    This is the load-bearing test: deleting code MUST NOT look like fixing it.
    """
    repo = fake_repo({"src/big.ts": "const x = 1;\n"})
    # Delete the module from disk.
    (Path(repo) / "src" / "big.ts").unlink()

    prior_findings = [
        _eslint_finding(file="src/big.ts", line=10, rule_id="no-unused-vars"),
        _eslint_finding(file="src/big.ts", line=20, rule_id="eqeqeq"),
        _eslint_finding(file="src/big.ts", line=30, rule_id="no-console"),
    ]
    prior = _report(prior_findings, date(2026, 5, 1))
    current = _report([], date(2026, 5, 28))  # all findings gone (file deleted)

    delta = compute_trend(prior, current, repo)

    statuses = [c.status for c in delta.changes]
    assert statuses.count("vanished_with_file") == 3
    assert statuses.count("resolved") == 0


def _sca_finding(*, tool: str, file: str, rule_id: str = "CVE-2026-0001") -> Finding:
    """A dependency-scanner finding in the path shape the named scanner emits."""
    return Finding(
        dimension="security",
        severity="major",
        file=file,
        line=1 if tool == "grype" else None,
        evidence_type="static",
        confidence="high",
        source_tool=tool,
        source_collector="sca_adapter",
        rule_id=rule_id,
        evidence=Evidence(tool=tool, parsed_value={"rule_id": rule_id}),
    )


def test_grype_root_relative_path_resolves_when_lockfile_present(fake_repo):
    """grype reports ``/requirements.txt``; a fixed CVE with the lockfile present is resolved."""
    repo = fake_repo({"requirements.txt": "requests==2.0.0\n"})
    prior = _report([_sca_finding(tool="grype", file="/requirements.txt")], date(2026, 5, 1))
    current = _report([], date(2026, 5, 28))

    delta = compute_trend(prior, current, repo)

    assert len(delta.changes) == 1
    assert delta.changes[0].status == "resolved"
    assert delta.changes[0].file == "requirements.txt"


def test_osv_file_uri_path_resolves_when_lockfile_present(fake_repo):
    """osv-scanner reports a ``file:///`` URI; a fixed CVE with the lockfile present is resolved."""
    repo = fake_repo({"requirements.txt": "requests==2.0.0\n"})
    uri = (Path(repo) / "requirements.txt").as_uri()
    prior = _report([_sca_finding(tool="osv-scanner", file=uri)], date(2026, 5, 1))
    current = _report([], date(2026, 5, 28))

    delta = compute_trend(prior, current, repo)

    assert len(delta.changes) == 1
    assert delta.changes[0].status == "resolved"
    assert delta.changes[0].file == "requirements.txt"


def test_grype_root_relative_path_with_lockfile_deleted_is_vanished(fake_repo):
    """A lockfile deleted from disk is not a fix, whatever the path shape."""
    repo = fake_repo({"requirements.txt": "requests==2.0.0\n"})
    (Path(repo) / "requirements.txt").unlink()
    prior = _report([_sca_finding(tool="grype", file="/requirements.txt")], date(2026, 5, 1))
    current = _report([], date(2026, 5, 28))

    delta = compute_trend(prior, current, repo)

    assert len(delta.changes) == 1
    assert delta.changes[0].status == "vanished_with_file"


def test_grype_root_relative_path_on_both_sides_is_still_present(fake_repo):
    repo = fake_repo({"requirements.txt": "requests==2.0.0\n"})
    prior = _report([_sca_finding(tool="grype", file="/requirements.txt")], date(2026, 5, 1))
    current = _report([_sca_finding(tool="grype", file="/requirements.txt")], date(2026, 5, 28))

    delta = compute_trend(prior, current, repo)

    assert len(delta.changes) == 1
    assert delta.changes[0].status == "still_present"


def test_path_escaping_repo_root_is_never_resolved(fake_repo):
    """A ``..`` path never resolves to a file outside the repo root."""
    repo = fake_repo({"requirements.txt": "requests==2.0.0\n"})
    (Path(repo).parent / "outside.txt").write_text("x\n")
    prior = _report([_sca_finding(tool="grype", file="../outside.txt")], date(2026, 5, 1))
    current = _report([], date(2026, 5, 28))

    delta = compute_trend(prior, current, repo)

    assert len(delta.changes) == 1
    assert delta.changes[0].status == "vanished_with_file"
