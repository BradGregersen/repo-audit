"""run_codeql contract (DSAST-01, Plan 16-04).

Pins the live-invocation lane:
  * default-OFF: should_run False -> unavailable, NO subprocess, SARIF never opened;
  * on a should_run + interpreted-lang repo, db-create + analyze are invoked
    (mocked run_tool) and the recorded SARIF routes through the SHARED
    ``sarif_to_findings`` (no fork) — candidate cap holds (a critical CodeQL
    result lands at severity='major' + confidence='candidate', never critical);
  * compiled-lang-only repo -> unavailable with the Pitfall-5 note;
  * run_tool sentinels: TIMED_OUT -> timeout; EXEC_FAILED / resolve None /
    missing SARIF -> unavailable; never raises;
  * all scratch (DB dir + SARIF) lands under the caller tempdir, never the repo.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("repo_audit.adapters.sarif", reason="shared SARIF parser missing")

from repo_audit.adapters import codeql as codeql_pkg
from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.codeql import run_codeql
from repo_audit.adapters.codeql.config import CodeQlConfig
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT
from repo_audit.schema.detection import DetectionResult, StackProfile

_CODEQL_SARIF = Path(__file__).parent.parent / "fixtures" / "codeql" / "analyze.sarif"


def _cfg(**overrides) -> CodeQlConfig:
    kw = dict(
        name="codeql",
        sarif_output="codeql.sarif",
        default_dimension="security",
        enabled=True,
        use_rights_attestation=True,
        use_rights="personal-own-code",
    )
    kw.update(overrides)
    return CodeQlConfig(**kw)


def _detection(stack: str, root: Path) -> DetectionResult:
    return DetectionResult(stacks=[StackProfile(stack=stack, root_dir=root)])


def _ok_invocation() -> InvocationResult:
    return InvocationResult(stdout="", stderr="", returncode=0)


def _wire_mock_run(monkeypatch, tmp_path, *, invocation=None, copy_sarif=True):
    """Mock resolve_tool to a fake binary + run_tool that 'writes' the SARIF."""
    monkeypatch.setattr(
        codeql_pkg, "resolve_tool", lambda *a, **k: Path("/usr/bin/codeql")
    )
    calls: list[list[str]] = []

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        calls.append(argv)
        # The analyze step is the one that writes the SARIF to --output.
        if copy_sarif and "analyze" in argv:
            out_idx = argv.index("--output") + 1
            shutil.copyfile(_CODEQL_SARIF, argv[out_idx])
        return invocation if invocation is not None else _ok_invocation()

    monkeypatch.setattr(codeql_pkg, "run_tool", fake_run_tool)
    return calls


def test_default_off_no_subprocess(tmp_path, monkeypatch):
    """should_run False -> unavailable, run_tool NEVER called."""
    called = {"n": 0}
    monkeypatch.setattr(
        codeql_pkg, "run_tool", lambda *a, **k: called.__setitem__("n", called["n"] + 1)
    )
    cfg = _cfg(enabled=False)
    result = run_codeql(
        tmp_path,
        base_env={},
        cfg=cfg,
        scratch_dir=tmp_path / "scratch",
        detection=_detection("python", tmp_path),
    )
    assert result.status == "unavailable"
    assert called["n"] == 0


def test_cfg_none_unavailable(tmp_path):
    result = run_codeql(
        tmp_path,
        base_env={},
        cfg=None,
        scratch_dir=tmp_path / "scratch",
        detection=_detection("python", tmp_path),
    )
    assert result.status == "unavailable"


def test_sarif_routes_through_shared_parser(tmp_path, monkeypatch):
    """A critical CodeQL result lands major+candidate (shared parser, candidate cap)."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _wire_mock_run(monkeypatch, tmp_path)
    result = run_codeql(
        tmp_path,
        base_env={},
        cfg=_cfg(),
        scratch_dir=scratch,
        detection=_detection("typescript-node", tmp_path),
    )
    assert result.status == "ok"
    assert result.findings, "expected at least one finding"
    assert result.source_tool == "codeql"
    for f in result.findings:
        if f.confidence == "candidate":
            assert f.severity not in ("critical", "blocker")
    # The error-level js/sql-injection result must be capped to major+candidate.
    sql = [f for f in result.findings if f.rule_id == "js/sql-injection"]
    assert sql and sql[0].severity == "major" and sql[0].confidence == "candidate"


def test_invokes_db_create_and_analyze(tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    calls = _wire_mock_run(monkeypatch, tmp_path)
    run_codeql(
        tmp_path,
        base_env={},
        cfg=_cfg(),
        scratch_dir=scratch,
        detection=_detection("python", tmp_path),
    )
    joined = [" ".join(c) for c in calls]
    assert any("database create" in j for j in joined)
    assert any("database analyze" in j for j in joined)
    # python repo -> --language=python
    assert any("--language=python" in c for c in calls)


def test_scratch_stays_outside_repo(tmp_path, monkeypatch):
    """DB dir + SARIF output land under scratch_dir, never the repo."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    seen_paths: list[str] = []

    monkeypatch.setattr(codeql_pkg, "resolve_tool", lambda *a, **k: Path("/usr/bin/codeql"))

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        seen_paths.extend(argv)
        if "analyze" in argv:
            shutil.copyfile(_CODEQL_SARIF, argv[argv.index("--output") + 1])
        return _ok_invocation()

    monkeypatch.setattr(codeql_pkg, "run_tool", fake_run_tool)
    run_codeql(
        repo,
        base_env={},
        cfg=_cfg(),
        scratch_dir=scratch,
        detection=_detection("python", repo),
    )
    # Every path that names the scratch DB / sarif must be under scratch, and the
    # repo must remain clean (no DB / sarif written under it).
    assert not list(repo.iterdir()), "repo must stay read-only (no scratch in repo)"


def test_compiled_lang_only_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(codeql_pkg, "resolve_tool", lambda *a, **k: Path("/usr/bin/codeql"))
    called = {"n": 0}
    monkeypatch.setattr(
        codeql_pkg, "run_tool", lambda *a, **k: called.__setitem__("n", called["n"] + 1)
    )
    result = run_codeql(
        tmp_path,
        base_env={},
        cfg=_cfg(),
        scratch_dir=tmp_path / "scratch",
        detection=_detection("kotlin-android", tmp_path),
    )
    assert result.status == "unavailable"
    assert "build" in result.notes.lower()
    assert called["n"] == 0


def test_timeout_maps_to_timeout(tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    timed_out = InvocationResult(stdout="", stderr="", returncode=TIMED_OUT)
    _wire_mock_run(monkeypatch, tmp_path, invocation=timed_out, copy_sarif=False)
    result = run_codeql(
        tmp_path,
        base_env={},
        cfg=_cfg(),
        scratch_dir=scratch,
        detection=_detection("python", tmp_path),
    )
    assert result.status == "timeout"


def test_exec_failed_unavailable(tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    failed = InvocationResult(stdout="", stderr="boom", returncode=EXEC_FAILED)
    _wire_mock_run(monkeypatch, tmp_path, invocation=failed, copy_sarif=False)
    result = run_codeql(
        tmp_path,
        base_env={},
        cfg=_cfg(),
        scratch_dir=scratch,
        detection=_detection("python", tmp_path),
    )
    assert result.status == "unavailable"


def test_resolve_none_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(codeql_pkg, "resolve_tool", lambda *a, **k: None)
    result = run_codeql(
        tmp_path,
        base_env={},
        cfg=_cfg(),
        scratch_dir=tmp_path / "scratch",
        detection=_detection("python", tmp_path),
    )
    assert result.status == "unavailable"


def test_missing_sarif_unavailable(tmp_path, monkeypatch):
    """analyze 'succeeds' (rc 0) but no SARIF written -> unavailable, never raises."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _wire_mock_run(monkeypatch, tmp_path, copy_sarif=False)
    result = run_codeql(
        tmp_path,
        base_env={},
        cfg=_cfg(),
        scratch_dir=scratch,
        detection=_detection("python", tmp_path),
    )
    assert result.status == "unavailable"
