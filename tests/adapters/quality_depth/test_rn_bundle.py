"""PERF-01 RN tier — collect_rn_bundle contract (Plan 15-03, Task 2).

Pins: default-OFF degrade (no artifact, no build → unavailable, zero run_tool),
existing-artifact measure (rn_bundle_size_summary carrying rn_bundle_bytes ==
st_size, evidence_type='static'), the opt-in throwaway Metro build, the MOD-1
git-status anti-dirtying tripwire, the oversized + regression triggers, the
build-cwd-is-the-tempdir-not-the-target assertion, and the no-import-subprocess
source assertion.
"""
from __future__ import annotations

import re
from pathlib import Path

from repo_audit.adapters.quality_depth import rn_bundle as rn_mod
from repo_audit.adapters.quality_depth.config import QualityDepthConfig
from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.quality_depth.rn_bundle import map_rn_bundle_bytes

_BANNED = re.compile(r"\b(enforced|secure|protected)\b", re.IGNORECASE)


def _ok() -> InvocationResult:
    return InvocationResult(stdout="", stderr="", returncode=0)


def _by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# --- mapper (pure) --------------------------------------------------------


def test_mapper_summary_carries_rn_bundle_bytes_static() -> None:
    """One static rn_bundle_size_summary carrying rn_bundle_bytes in parsed_value."""
    findings = map_rn_bundle_bytes(100000, config=QualityDepthConfig())
    summary = _by_rule(findings, "rn_bundle_size_summary")[0]
    assert summary.evidence.parsed_value["rn_bundle_bytes"] == 100000
    assert summary.evidence_type == "static"
    assert summary.confidence == "candidate"
    assert summary.severity in {"info", "minor", "major"}


def test_mapper_oversized_above_budget() -> None:
    """bytes > rn_budget_bytes (512000) → oversized finding."""
    findings = map_rn_bundle_bytes(600000, config=QualityDepthConfig())
    assert len(_by_rule(findings, "rn_bundle_oversized")) == 1


def test_mapper_no_oversized_under_budget() -> None:
    findings = map_rn_bundle_bytes(100000, config=QualityDepthConfig())
    assert _by_rule(findings, "rn_bundle_oversized") == []


def test_mapper_regression_only_with_prior_past_both_gates() -> None:
    """prior given AND growth > pct AND > floor → regression finding."""
    findings = map_rn_bundle_bytes(
        200000, config=QualityDepthConfig(), prior_rn_bytes=100000
    )
    assert len(_by_rule(findings, "rn_bundle_regression")) == 1


def test_mapper_no_regression_without_prior() -> None:
    findings = map_rn_bundle_bytes(200000, config=QualityDepthConfig())
    assert _by_rule(findings, "rn_bundle_regression") == []


def test_mapper_verify_phrasing_self_enforced() -> None:
    findings = map_rn_bundle_bytes(
        600000, config=QualityDepthConfig(), prior_rn_bytes=100000
    )
    for f in findings:
        assert "verify" in f.recommendation.lower()
        assert _BANNED.search(f.recommendation) is None


# --- collector: degrade + existing artifact ------------------------------


def test_no_build_no_artifact_unavailable_zero_run_tool(tmp_path, monkeypatch) -> None:
    """qd_build=False AND no existing bundle → unavailable, run_tool zero calls."""
    calls: list = []

    def _spy(*a, **k):  # pragma: no cover - must not run
        calls.append(1)
        return _ok()

    monkeypatch.setattr(rn_mod, "run_tool", _spy)
    result = rn_mod.collect_rn_bundle(
        tmp_path, {}, qd_build=False, config=QualityDepthConfig()
    )
    assert result.status == "unavailable"
    assert calls == []


def test_existing_artifact_measured_static(tmp_path, qd_fixtures_dir) -> None:
    """An existing index.android.bundle → summary bytes == its st_size, static."""
    repo = tmp_path / "repo"
    build_dir = repo / "android" / "app" / "build"
    build_dir.mkdir(parents=True)
    artifact = build_dir / "index.android.bundle"
    fixture = qd_fixtures_dir / "index.android.bundle"
    artifact.write_bytes(fixture.read_bytes())
    expected = artifact.stat().st_size

    result = rn_mod.collect_rn_bundle(
        repo, {}, qd_build=False, config=QualityDepthConfig()
    )
    assert result.status == "ok"
    summary = _by_rule(result.findings, "rn_bundle_size_summary")[0]
    assert summary.evidence.parsed_value["rn_bundle_bytes"] == expected
    assert summary.evidence_type == "static"


# --- collector: opt-in build path ----------------------------------------


def _wire_clean_build(monkeypatch, tmp_path):
    """Make resolve/run_tool/git-status produce a clean successful build."""
    monkeypatch.setattr(rn_mod, "resolve_tool", lambda *a, **k: Path("/x/react-native"))
    # tree stays clean → no offenders
    monkeypatch.setattr(rn_mod, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(rn_mod, "diff_git_status", lambda pre, post: [])

    cwds: list = []

    def _fake_run(argv, *, env, cwd, timeout_seconds):
        cwds.append(str(cwd))
        # git archive: produce a tarball; tar -xf: make work dir; rn bundle: write
        if "archive" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"TAR")
            return _ok()
        if argv[0] == "tar":
            return _ok()
        if "bundle" in argv:
            out = Path(argv[argv.index("--bundle-output") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(b"x" * 12345)
            return _ok()
        return _ok()

    monkeypatch.setattr(rn_mod, "run_tool", _fake_run)
    return cwds


def test_build_path_emits_finding_and_builds_in_tempdir(tmp_path, monkeypatch) -> None:
    """qd_build=True with a mocked clean build → a size finding; cwd is the copy."""
    repo = tmp_path / "repo"
    repo.mkdir()
    cwds = _wire_clean_build(monkeypatch, tmp_path)

    result = rn_mod.collect_rn_bundle(
        repo, {}, qd_build=True, config=QualityDepthConfig()
    )
    assert result.status == "ok"
    summary = _by_rule(result.findings, "rn_bundle_size_summary")[0]
    assert summary.evidence.parsed_value["rn_bundle_bytes"] == 12345
    # the bundle build cwd is NEVER the target repo
    assert all(str(repo.resolve()) != c for c in cwds)


def test_dirtying_build_returns_unavailable_no_size(tmp_path, monkeypatch) -> None:
    """diff_git_status → offenders → unavailable with MOD-1 note, NO size finding."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _wire_clean_build(monkeypatch, tmp_path)
    # override the tripwire to simulate a dirtying run
    monkeypatch.setattr(
        rn_mod, "diff_git_status", lambda pre, post: [" M src/leaked.txt"]
    )

    result = rn_mod.collect_rn_bundle(
        repo, {}, qd_build=True, config=QualityDepthConfig()
    )
    assert result.status == "unavailable"
    assert "MOD-1" in result.notes
    assert _by_rule(result.findings, "rn_bundle_size_summary") == []


def test_build_timeout_maps_to_timeout(tmp_path, monkeypatch) -> None:
    """A TIMED_OUT on the bundle step → status timeout."""
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(rn_mod, "resolve_tool", lambda *a, **k: Path("/x/react-native"))
    monkeypatch.setattr(rn_mod, "snapshot_git_status", lambda repo: set())
    monkeypatch.setattr(rn_mod, "diff_git_status", lambda pre, post: [])

    def _fake_run(argv, *, env, cwd, timeout_seconds):
        if "archive" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"TAR")
            return _ok()
        if argv[0] == "tar":
            return _ok()
        if "bundle" in argv:
            return InvocationResult(stdout="", stderr="", returncode=-2)  # TIMED_OUT
        return _ok()

    monkeypatch.setattr(rn_mod, "run_tool", _fake_run)
    result = rn_mod.collect_rn_bundle(
        repo, {}, qd_build=True, config=QualityDepthConfig()
    )
    assert result.status == "timeout"


def test_rn_bundle_module_has_no_import_subprocess() -> None:
    """All subprocess via run_tool — no direct subprocess import."""
    src = Path(rn_mod.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in src


def test_collect_rn_bundle_exported_on_package() -> None:
    from repo_audit.adapters import quality_depth as qd

    assert hasattr(qd, "collect_rn_bundle")
