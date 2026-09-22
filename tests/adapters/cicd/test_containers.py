"""CICD-02 containers-collector contract (Plan 13-03, Wave-1).

The opening ``pytest.importorskip`` keeps this module SKIPPED until the Wave-1
implementation ``repo_audit.adapters.cicd.containers`` (hadolint) lands
(the 03-01b SKIPPED->ACTIVE-on-landing discipline), at which point these contract
assertions activate automatically. The function NAMES match the 13-VALIDATION.md
Per-Task Verification Map (``test_hadolint_perfile`` /
``test_hadolint_no_dockerfile_unavailable``) and must NOT be renamed.

hadolint stdout is fed via ``pytest-subprocess`` (``fp``) as canned SARIF; the
absent-binary path monkeypatches ``containers.resolve_tool`` to ``None``. The
collector gates on PARSE success, never on returncode (hadolint ``--no-fail``
exits 0 always) — see Pitfall 6. hadolint is invoked ONCE PER Dockerfile with the
real file path as a discrete argv element (NEVER stdin — Pitfall 2), so the
finding carries the real path, not the ``"-"`` stdin sentinel.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

containers = pytest.importorskip(
    "repo_audit.adapters.cicd.containers",
    reason="optional module repo_audit.adapters.cicd.containers not importable — feature not present in this build, or the install is incomplete",
)

# A fake resolved-binary path so the recorded-fixture parse tests are HERMETIC —
# they exercise the parse path via pytest-subprocess (``fp``) regardless of
# whether hadolint happens to be installed on the test host.
_FAKE_BIN = Path("/usr/bin/__hadolint__")


def _stub_resolve(monkeypatch):
    monkeypatch.setattr(
        containers, "resolve_tool", lambda *a, **k: _FAKE_BIN, raising=False
    )


def test_hadolint_perfile(fake_cicd_repo, hadolint_sarif_path, load_sarif, fp, monkeypatch):
    """hadolint SARIF per Dockerfile -> findings; the file is a REAL path, NOT "-".

    Feed the recorded hadolint SARIF (uri:"-") as the tool's stdout with
    returncode 0 (``--no-fail``), call collect_hadolint over a repo WITH a
    Dockerfile, and assert the CICD-02 security-finding contract. Because the
    collector invokes hadolint with the REAL Dockerfile path as argv (Pitfall 2),
    each finding's ``file`` is normalized to that real path — never the ``"-"``
    stdin sentinel.
    """
    repo = fake_cicd_repo(dockerfile=True)
    _stub_resolve(monkeypatch)
    sarif_bytes = json.dumps(load_sarif(hadolint_sarif_path))
    fp.register([fp.any()], stdout=sarif_bytes, returncode=0, occurrences=10)

    result = containers.collect_hadolint(repo, env={})
    findings = result.findings

    assert result.status == "ok"
    assert len(findings) >= 1
    assert all(f.source_tool == "hadolint" for f in findings)
    assert all(f.dimension == "security" for f in findings)
    assert all(f.evidence_type == "static" for f in findings)
    assert all(f.confidence == "candidate" for f in findings)
    # Pitfall 2: the file is the REAL Dockerfile path, never the "-" stdin sentinel.
    assert all(f.file not in (None, "", "-") for f in findings)
    dockerfile = str(repo / "Dockerfile")
    assert all(f.file == dockerfile for f in findings)


def test_hadolint_perfile_multiple_dockerfiles(
    fake_cicd_repo, hadolint_sarif_path, load_sarif, fp, monkeypatch
):
    """Two Dockerfiles -> findings merged across BOTH, each carrying its own path."""
    repo = fake_cicd_repo(dockerfile=True)
    # add a second Dockerfile
    (repo / "Dockerfile.prod").write_text("FROM node:20\n", encoding="utf-8")
    _stub_resolve(monkeypatch)
    sarif_bytes = json.dumps(load_sarif(hadolint_sarif_path))
    fp.register([fp.any()], stdout=sarif_bytes, returncode=0, occurrences=10)

    result = containers.collect_hadolint(repo, env={})

    assert result.status == "ok"
    paths = {f.file for f in result.findings}
    # findings from both files, each stamped with its own real path
    assert str(repo / "Dockerfile") in paths
    assert str(repo / "Dockerfile.prod") in paths


def test_hadolint_no_dockerfile_unavailable(fake_cicd_repo, monkeypatch):
    """No Dockerfile -> status=='unavailable' WITHOUT invoking the tool."""
    repo = fake_cicd_repo()  # all surfaces False

    def _boom(*a, **k):  # pragma: no cover - asserts the tool is never resolved
        raise AssertionError("resolve_tool must not be called when no Dockerfile exists")

    monkeypatch.setattr(containers, "resolve_tool", _boom, raising=False)

    result = containers.collect_hadolint(repo, env={})

    assert result.status == "unavailable"
    assert result.findings == []
    assert "dockerfile" in result.notes.lower()


def test_hadolint_absent_tool_unavailable(fake_cicd_repo, monkeypatch):
    """hadolint not on PATH -> status=='unavailable', no raise."""
    repo = fake_cicd_repo(dockerfile=True)
    monkeypatch.setattr(containers, "resolve_tool", lambda *a, **k: None, raising=False)

    result = containers.collect_hadolint(repo, env={})

    assert result.status == "unavailable"
    assert result.findings == []


def test_hadolint_nonzero_exit_but_parseable(
    fake_cicd_repo, hadolint_sarif_path, load_sarif, fp, monkeypatch
):
    """Non-zero exit BUT parseable SARIF -> 'ok' (gate on parse, NOT returncode)."""
    repo = fake_cicd_repo(dockerfile=True)
    _stub_resolve(monkeypatch)
    sarif_bytes = json.dumps(load_sarif(hadolint_sarif_path))
    fp.register([fp.any()], stdout=sarif_bytes, returncode=1, occurrences=10)

    result = containers.collect_hadolint(repo, env={})

    assert result.status == "ok"
    assert len(result.findings) >= 1


def test_hadolint_garbage_stdout_unavailable(fake_cicd_repo, fp, monkeypatch):
    """Non-JSON stdout -> status='unavailable' (no parseable SARIF), no raise."""
    repo = fake_cicd_repo(dockerfile=True)
    _stub_resolve(monkeypatch)
    fp.register([fp.any()], stdout="not json", returncode=0, occurrences=10)

    result = containers.collect_hadolint(repo, env={})

    assert result.status == "unavailable"


def test_hadolint_timeout(fake_cicd_repo, fp, monkeypatch):
    """run_tool TIMED_OUT on a file -> status='timeout' (short-circuits the collector)."""
    repo = fake_cicd_repo(dockerfile=True)
    _stub_resolve(monkeypatch)

    from repo_audit.adapters import toolops

    def _timed_out(*a, **k):
        return toolops.InvocationResult(stdout="", stderr="", returncode=toolops.TIMED_OUT)

    monkeypatch.setattr(containers, "run_tool", _timed_out, raising=False)

    result = containers.collect_hadolint(repo, env={})

    assert result.status == "timeout"


def test_hadolint_exec_failed(fake_cicd_repo, monkeypatch):
    """run_tool EXEC_FAILED -> status='unavailable', no raise."""
    repo = fake_cicd_repo(dockerfile=True)
    _stub_resolve(monkeypatch)

    from repo_audit.adapters import toolops

    def _exec_failed(*a, **k):
        return toolops.InvocationResult(
            stdout="", stderr="boom", returncode=toolops.EXEC_FAILED
        )

    monkeypatch.setattr(containers, "run_tool", _exec_failed, raising=False)

    result = containers.collect_hadolint(repo, env={})

    assert result.status == "unavailable"
