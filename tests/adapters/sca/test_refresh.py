"""Task 2 (Plan 07-05): refresh_vuln_db — the only snapshot-advance path (D-07-03).

``refresh_vuln_db`` advances BOTH osv and grype snapshots in ONE pass and is the
SOLE code path that passes ``--download-offline-databases`` / ``db update``. It
mirrors typescript/refresh.py's never-raises + scrub-secrets + redact-tail
posture, but invokes through the shared ``run_tool`` seam (not subprocess.run).
"""
from __future__ import annotations

from pathlib import Path

import repo_audit.adapters.sca.refresh as refreshmod
from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.sca.refresh import ScaRefreshResult, refresh_vuln_db


def _ok(argv: list[str]) -> InvocationResult:
    return InvocationResult(stdout="{}", stderr="", returncode=0, command=argv)


def test_refreshes_both_sources_with_download_flags(monkeypatch, tmp_path):
    """osv gets --download-offline-databases; grype gets db update."""
    calls: list[list[str]] = []

    def fake_resolve(tool, target, **_kw):
        return tmp_path / tool

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        calls.append(argv)
        return _ok(argv)

    monkeypatch.setattr(refreshmod, "resolve_tool", fake_resolve)
    monkeypatch.setattr(refreshmod, "run_tool", fake_run_tool)

    result = refresh_vuln_db({"PATH": "/usr/bin"})

    assert isinstance(result, ScaRefreshResult)
    assert result.status == "ok"
    flat = [tok for argv in calls for tok in argv]
    assert "--download-offline-databases" in flat
    assert "db" in flat and "update" in flat
    assert result.osv_status == "ok"
    assert result.grype_status == "ok"


def test_never_raises_on_missing_binaries(monkeypatch):
    """Both tools absent → status reflects skipped/failed, never raises."""
    monkeypatch.setattr(refreshmod, "resolve_tool", lambda tool, target, **_kw: None)
    # run_tool must not even be reached; make it explode if it is.
    monkeypatch.setattr(
        refreshmod, "run_tool",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run")),
    )
    result = refresh_vuln_db({})
    assert result.osv_status == "skipped"
    assert result.grype_status == "skipped"
    # Both skipped → overall not "ok" (nothing advanced).
    assert result.status in {"skipped", "failed"}


def test_exec_failed_maps_to_failed(monkeypatch, tmp_path):
    from repo_audit.adapters.toolops import EXEC_FAILED

    monkeypatch.setattr(refreshmod, "resolve_tool", lambda tool, target, **_kw: tmp_path / tool)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        return InvocationResult(stdout="", stderr="boom", returncode=EXEC_FAILED, command=argv)

    monkeypatch.setattr(refreshmod, "run_tool", fake_run_tool)
    result = refresh_vuln_db({})
    assert result.osv_status == "failed"
    assert result.grype_status == "failed"


def test_timeout_maps_to_timeout(monkeypatch, tmp_path):
    from repo_audit.adapters.toolops import TIMED_OUT

    monkeypatch.setattr(refreshmod, "resolve_tool", lambda tool, target, **_kw: tmp_path / tool)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        return InvocationResult(stdout="", stderr="slow", returncode=TIMED_OUT, command=argv)

    monkeypatch.setattr(refreshmod, "run_tool", fake_run_tool)
    result = refresh_vuln_db({})
    assert result.osv_status == "timeout"
    assert result.grype_status == "timeout"


def test_secrets_scrubbed_from_child_env(monkeypatch, tmp_path):
    """Secret-shaped env vars are dropped before invoking the tools."""
    seen_envs: list[dict] = []

    monkeypatch.setattr(refreshmod, "resolve_tool", lambda tool, target, **_kw: tmp_path / tool)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        seen_envs.append(env)
        return _ok(argv)

    monkeypatch.setattr(refreshmod, "run_tool", fake_run_tool)
    refresh_vuln_db({"AWS_SECRET": "x", "GITHUB_TOKEN": "y", "PATH": "/usr/bin"})
    assert seen_envs
    for env in seen_envs:
        assert "AWS_SECRET" not in env
        assert "GITHUB_TOKEN" not in env


def test_db_env_layered_before_invocation(monkeypatch, tmp_path):
    """The DB-cache env keys are present in the child env (build_sca_env layered)."""
    seen_envs: list[dict] = []
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr(refreshmod, "resolve_tool", lambda tool, target, **_kw: tmp_path / tool)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        seen_envs.append(env)
        return _ok(argv)

    monkeypatch.setattr(refreshmod, "run_tool", fake_run_tool)
    refresh_vuln_db({"PATH": "/usr/bin"})
    assert seen_envs
    for env in seen_envs:
        assert "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY" in env
        assert "GRYPE_DB_CACHE_DIR" in env


# ---- The osv seed target: a packaged, tool-controlled manifest directory. ----

_SEED_MANIFESTS = (
    "requirements.txt",
    "package-lock.json",
    "gradle.lockfile",
    "go.mod",
    "Cargo.lock",
    "packages.lock.json",
)


def test_osv_download_targets_packaged_seed_manifests(monkeypatch, tmp_path):
    """osv downloads against the packaged seed dir holding one manifest per ecosystem."""
    osv_calls: list[tuple[list[str], object]] = []

    monkeypatch.setattr(refreshmod, "resolve_tool", lambda tool, target, **_kw: tmp_path / tool)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        if "--download-offline-databases" in argv:
            osv_calls.append((argv, cwd))
        return _ok(argv)

    monkeypatch.setattr(refreshmod, "run_tool", fake_run_tool)
    refresh_vuln_db({"PATH": "/usr/bin"})

    assert len(osv_calls) == 1
    argv, cwd = osv_calls[0]
    target = Path(argv[-1])
    assert target.name == "seed_manifests"
    assert target.parent == Path(refreshmod.__file__).parent
    assert target.is_dir()
    present = {p.name for p in target.iterdir()}
    for name in _SEED_MANIFESTS:
        assert name in present, f"missing seed manifest {name}"
    # The scan target is never the working directory the tool runs in.
    assert Path(cwd) != target


def test_seed_manifests_name_only_placeholder_packages():
    """Every seed manifest names a placeholder package at 0.0.0 (no advisory can match)."""
    seed = Path(refreshmod.__file__).parent / "seed_manifests"
    for name in _SEED_MANIFESTS:
        text = (seed / name).read_text(encoding="utf-8")
        assert "repo-audit-seed-placeholder" in text, name
        assert "0.0.0" in text, name


def test_osv_download_exit_one_is_ok(monkeypatch, tmp_path):
    """osv exits 1 when the download pass also finds vulnerabilities: still ok."""
    monkeypatch.setattr(refreshmod, "resolve_tool", lambda tool, target, **_kw: tmp_path / tool)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        rc = 1 if "--download-offline-databases" in argv else 0
        return InvocationResult(stdout="{}", stderr="", returncode=rc, command=argv)

    monkeypatch.setattr(refreshmod, "run_tool", fake_run_tool)
    result = refresh_vuln_db({"PATH": "/usr/bin"})
    assert result.osv_status == "ok"
    assert result.grype_status == "ok"
    assert result.status == "ok"


def test_osv_download_other_nonzero_is_failed(monkeypatch, tmp_path):
    """Any osv exit other than 0/1 during the download is failed; grype unchanged."""
    monkeypatch.setattr(refreshmod, "resolve_tool", lambda tool, target, **_kw: tmp_path / tool)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        rc = 127 if "--download-offline-databases" in argv else 1
        return InvocationResult(stdout="{}", stderr="", returncode=rc, command=argv)

    monkeypatch.setattr(refreshmod, "run_tool", fake_run_tool)
    result = refresh_vuln_db({"PATH": "/usr/bin"})
    assert result.osv_status == "failed"
    # grype keeps its strict classification: exit 1 is a failure for `db update`.
    assert result.grype_status == "failed"
