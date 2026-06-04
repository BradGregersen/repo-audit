"""CICD-02 IaC-collector contract (Plan 13-03, Wave-2).

The opening ``pytest.importorskip`` keeps this module SKIPPED until the Wave-2
implementation ``repo_audit.adapters.cicd.iac`` (checkov) lands (the 03-01b
SKIPPED->ACTIVE-on-landing discipline), at which point these contract assertions
activate automatically. The function NAMES match the 13-VALIDATION.md Per-Task
Verification Map (``test_checkov_framework_scoped`` /
``test_checkov_no_iac_unavailable``) and must NOT be renamed.

checkov writes its SARIF to ``results_sarif.sarif`` inside ``--output-file-path``
(NOT cleanly to stdout — Pitfall 4); the collector reads + parses that FILE. The
output dir is a tempdir OUTSIDE the read-only target repo (REP-03 / T-13-WRITE).
The ``--framework`` argv EXCLUDES dockerfile/github_actions/secrets so checkov
never double-covers hadolint/zizmor (Pitfall 3 / T-13-DBLCOVER); a leaked
``CKV_DOCKER_``/``CKV_GHA_`` rule_id is the warning sign.

run_tool is stubbed to SIMULATE checkov writing the recorded SARIF fixture into
the supplied out_dir, so the parse path runs hermetically regardless of whether
checkov is installed on the test host.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

iac = pytest.importorskip(
    "repo_audit.adapters.cicd.iac",
    reason="Wave 2 (Plan 03/04) not yet landed — cicd.iac missing",
)

_FAKE_BIN = Path("/usr/bin/__checkov__")


def _stub_resolve(monkeypatch):
    monkeypatch.setattr(iac, "resolve_tool", lambda *a, **k: _FAKE_BIN, raising=False)


def _stub_run_writes(monkeypatch, sarif_dict, *, returncode=0):
    """Stub run_tool so it writes ``results_sarif.sarif`` into the out_dir argv.

    Mirrors checkov's real behavior: SARIF lands in the ``--output-file-path``
    directory as ``results_sarif.sarif`` (Assumption A2). The stub extracts that
    dir from the argv, writes the fixture there, and returns the InvocationResult.
    """
    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        out_dir = Path(argv[argv.index("--output-file-path") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "results_sarif.sarif").write_text(
            json.dumps(sarif_dict), encoding="utf-8"
        )
        return toolops.InvocationResult(stdout="banner noise", stderr="", returncode=returncode)

    monkeypatch.setattr(iac, "run_tool", _run, raising=False)


def test_checkov_framework_scoped(
    fake_cicd_repo, checkov_sarif_path, load_sarif, fp, monkeypatch, tmp_path
):
    """checkov SARIF (from the written FILE) -> findings; NO CKV_DOCKER_/CKV_GHA_.

    Build a repo WITH IaC, simulate checkov writing results_sarif.sarif into an
    out_dir OUTSIDE the repo, and assert the CICD-02 security-finding contract +
    the framework-scoping guard.
    """
    repo = fake_cicd_repo(iac=True)
    out_dir = tmp_path / "checkov_out"  # OUTSIDE repo
    _stub_resolve(monkeypatch)
    _stub_run_writes(monkeypatch, load_sarif(checkov_sarif_path))

    result = iac.collect_checkov(repo, env={}, out_dir=out_dir)
    findings = result.findings

    assert result.status == "ok"
    assert len(findings) >= 1
    assert all(f.source_tool == "checkov" for f in findings)
    assert all(f.dimension == "security" for f in findings)
    assert all(f.evidence_type == "static" for f in findings)
    assert all(f.confidence == "candidate" for f in findings)
    # Pitfall 3 / T-13-DBLCOVER: framework scoping excludes dockerfile/github_actions.
    assert all(not f.rule_id.startswith("CKV_DOCKER_") for f in findings)
    assert all(not f.rule_id.startswith("CKV_GHA_") for f in findings)


def test_checkov_severity_error_capped_at_major(
    fake_cicd_repo, checkov_sarif_path, load_sarif, monkeypatch, tmp_path
):
    """A SARIF error-level result maps to major-capped-at-candidate (SCH-04)."""
    repo = fake_cicd_repo(iac=True)
    out_dir = tmp_path / "checkov_out"
    _stub_resolve(monkeypatch)
    _stub_run_writes(monkeypatch, load_sarif(checkov_sarif_path))

    result = iac.collect_checkov(repo, env={}, out_dir=out_dir)

    assert result.status == "ok"
    # checkov defaultConfiguration.level=error -> critical faithful, capped to major
    # at candidate confidence (SCH-04). No critical/blocker leaks at candidate.
    assert all(f.severity not in ("critical", "blocker") for f in result.findings)
    assert any(f.severity == "major" for f in result.findings)


def test_checkov_argv_framework_scoped_and_offrepo(
    fake_cicd_repo, checkov_sarif_path, load_sarif, monkeypatch, tmp_path
):
    """The argv carries --soft-fail + --framework (excluding dockerfile/gha/secrets)
    and the SARIF out_dir is OUTSIDE the repo."""
    repo = fake_cicd_repo(iac=True)
    out_dir = tmp_path / "checkov_out"
    _stub_resolve(monkeypatch)

    captured = {}
    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        captured["argv"] = argv
        d = Path(argv[argv.index("--output-file-path") + 1])
        d.mkdir(parents=True, exist_ok=True)
        (d / "results_sarif.sarif").write_text(
            json.dumps(load_sarif(checkov_sarif_path)), encoding="utf-8"
        )
        return toolops.InvocationResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(iac, "run_tool", _run, raising=False)

    result = iac.collect_checkov(repo, env={}, out_dir=out_dir)
    argv = captured["argv"]

    assert result.status == "ok"
    assert "--soft-fail" in argv
    assert "--framework" in argv
    # offline pin: no remote Terraform module fetch during a scan
    # (WR-01 / T-13-EGRESS — the checkov analogue of zizmor's --offline).
    assert "--download-external-modules" in argv
    assert argv[argv.index("--download-external-modules") + 1] == "false"
    # framework scoping EXCLUDES double-covered surfaces (Pitfall 3)
    assert "dockerfile" not in argv
    assert "github_actions" not in argv
    assert "secrets" not in argv
    # the out_dir is NOT under the repo (REP-03 / T-13-WRITE)
    od = Path(argv[argv.index("--output-file-path") + 1]).resolve()
    assert repo.resolve() != od and repo.resolve() not in od.parents


def test_checkov_default_out_dir_outside_repo(
    fake_cicd_repo, checkov_sarif_path, load_sarif, monkeypatch
):
    """With no out_dir supplied, the collector picks a tempdir OUTSIDE the repo."""
    repo = fake_cicd_repo(iac=True)
    _stub_resolve(monkeypatch)

    captured = {}
    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        d = Path(argv[argv.index("--output-file-path") + 1])
        captured["out_dir"] = d
        d.mkdir(parents=True, exist_ok=True)
        (d / "results_sarif.sarif").write_text(
            json.dumps(load_sarif(checkov_sarif_path)), encoding="utf-8"
        )
        return toolops.InvocationResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(iac, "run_tool", _run, raising=False)

    result = iac.collect_checkov(repo, env={})

    assert result.status == "ok"
    od = captured["out_dir"].resolve()
    assert repo.resolve() != od and repo.resolve() not in od.parents


def test_checkov_no_iac_unavailable(fake_cicd_repo, monkeypatch):
    """No IaC config -> status=='unavailable' WITHOUT invoking checkov."""
    repo = fake_cicd_repo()  # all surfaces False

    def _boom(*a, **k):  # pragma: no cover - asserts checkov is never resolved
        raise AssertionError("resolve_tool must not be called when no IaC exists")

    monkeypatch.setattr(iac, "resolve_tool", _boom, raising=False)

    result = iac.collect_checkov(repo, env={})

    assert result.status == "unavailable"
    assert result.findings == []
    assert "iac" in result.notes.lower() or "config" in result.notes.lower()


def test_checkov_absent_tool_unavailable(fake_cicd_repo, monkeypatch):
    """checkov not on PATH -> status=='unavailable', no raise."""
    repo = fake_cicd_repo(iac=True)
    monkeypatch.setattr(iac, "resolve_tool", lambda *a, **k: None, raising=False)

    result = iac.collect_checkov(repo, env={})

    assert result.status == "unavailable"
    assert result.findings == []


def test_checkov_missing_sarif_file_unavailable(fake_cicd_repo, monkeypatch, tmp_path):
    """run succeeds but no results_sarif.sarif written -> unavailable, no crash."""
    repo = fake_cicd_repo(iac=True)
    out_dir = tmp_path / "checkov_out"
    _stub_resolve(monkeypatch)

    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        # does NOT write the SARIF file
        return toolops.InvocationResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(iac, "run_tool", _run, raising=False)

    result = iac.collect_checkov(repo, env={}, out_dir=out_dir)

    assert result.status == "unavailable"
    assert "sarif" in result.notes.lower()


def test_checkov_timeout(fake_cicd_repo, monkeypatch, tmp_path):
    """run_tool TIMED_OUT -> status='timeout'."""
    repo = fake_cicd_repo(iac=True)
    out_dir = tmp_path / "checkov_out"
    _stub_resolve(monkeypatch)

    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        return toolops.InvocationResult(stdout="", stderr="", returncode=toolops.TIMED_OUT)

    monkeypatch.setattr(iac, "run_tool", _run, raising=False)

    result = iac.collect_checkov(repo, env={}, out_dir=out_dir)

    assert result.status == "timeout"


def test_checkov_exec_failed(fake_cicd_repo, monkeypatch, tmp_path):
    """run_tool EXEC_FAILED -> status='unavailable', no raise."""
    repo = fake_cicd_repo(iac=True)
    out_dir = tmp_path / "checkov_out"
    _stub_resolve(monkeypatch)

    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        return toolops.InvocationResult(
            stdout="", stderr="boom", returncode=toolops.EXEC_FAILED
        )

    monkeypatch.setattr(iac, "run_tool", _run, raising=False)

    result = iac.collect_checkov(repo, env={}, out_dir=out_dir)

    assert result.status == "unavailable"
