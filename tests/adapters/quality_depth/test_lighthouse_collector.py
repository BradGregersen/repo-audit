"""PERF-01 web tier — collect_lighthouse collector contract (Plan 15-03, Task 1).

Pins the live-URL-gated never-raising collector: GATE 1 (no URL -> unavailable,
ZERO egress: run_tool spy records zero calls), resolve None -> unavailable, a
mocked run_tool producing an LHR file -> Findings, TIMED_OUT -> timeout. Plus the
no-``import subprocess`` source assertion.
"""
from __future__ import annotations

import json
from pathlib import Path

from repo_audit.adapters.quality_depth import lighthouse as lh_mod
from repo_audit.adapters.quality_depth.config import QualityDepthConfig
from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT


def _ok(stdout: str = "") -> InvocationResult:
    return InvocationResult(stdout=stdout, stderr="", returncode=0)


def test_no_live_url_degrades_unavailable_zero_egress(tmp_path, monkeypatch) -> None:
    """GATE 1: no live_url → unavailable, run_tool NEVER called (no egress)."""
    calls: list = []

    def _spy(*args, **kwargs):  # pragma: no cover - must not run
        calls.append((args, kwargs))
        return _ok()

    monkeypatch.setattr(lh_mod, "run_tool", _spy)
    monkeypatch.setattr(lh_mod, "resolve_tool", lambda *a, **k: Path("/x/lighthouse"))

    result = lh_mod.collect_lighthouse(
        tmp_path, {}, live_url=None, config=QualityDepthConfig(), timeout_seconds=120
    )
    assert result.status == "unavailable"
    assert calls == []  # ZERO egress


def test_resolve_none_degrades_unavailable(tmp_path, monkeypatch) -> None:
    """resolve_tool None → unavailable, run_tool not invoked."""
    calls: list = []

    def _spy(*args, **kwargs):  # pragma: no cover - must not run
        calls.append(1)
        return _ok()

    monkeypatch.setattr(lh_mod, "resolve_tool", lambda *a, **k: None)
    monkeypatch.setattr(lh_mod, "run_tool", _spy)
    result = lh_mod.collect_lighthouse(
        tmp_path,
        {},
        live_url="https://example.com",
        config=QualityDepthConfig(),
        timeout_seconds=120,
    )
    assert result.status == "unavailable"
    assert calls == []


def test_success_reads_lhr_file_and_maps(tmp_path, monkeypatch, qd_fixtures_dir) -> None:
    """A mocked run_tool that writes an LHR file → ok with mapped findings."""
    lhr = json.loads(
        (qd_fixtures_dir / "lighthouse_lhr.json").read_text(encoding="utf-8")
    )

    def _fake_run(argv, *, env, cwd, timeout_seconds):
        # locate the --output-path target and write the LHR there
        out = Path(argv[argv.index("--output-path") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(lhr), encoding="utf-8")
        return _ok()

    monkeypatch.setattr(lh_mod, "resolve_tool", lambda *a, **k: Path("/x/lighthouse"))
    monkeypatch.setattr(lh_mod, "run_tool", _fake_run)
    result = lh_mod.collect_lighthouse(
        tmp_path,
        {},
        live_url="https://example.com",
        config=QualityDepthConfig(),
        timeout_seconds=120,
    )
    assert result.status == "ok"
    assert any(f.rule_id == "lighthouse_perf_summary" for f in result.findings)
    assert any(f.rule_id == "web_transfer_oversized" for f in result.findings)


def test_timeout_maps_to_timeout(tmp_path, monkeypatch) -> None:
    """TIMED_OUT sentinel → status timeout."""
    monkeypatch.setattr(lh_mod, "resolve_tool", lambda *a, **k: Path("/x/lighthouse"))
    monkeypatch.setattr(
        lh_mod,
        "run_tool",
        lambda *a, **k: InvocationResult(stdout="", stderr="", returncode=TIMED_OUT),
    )
    result = lh_mod.collect_lighthouse(
        tmp_path,
        {},
        live_url="https://example.com",
        config=QualityDepthConfig(),
        timeout_seconds=1,
    )
    assert result.status == "timeout"


def test_exec_failed_maps_to_unavailable(tmp_path, monkeypatch) -> None:
    """EXEC_FAILED sentinel → unavailable."""
    monkeypatch.setattr(lh_mod, "resolve_tool", lambda *a, **k: Path("/x/lighthouse"))
    monkeypatch.setattr(
        lh_mod,
        "run_tool",
        lambda *a, **k: InvocationResult(stdout="", stderr="boom", returncode=EXEC_FAILED),
    )
    result = lh_mod.collect_lighthouse(
        tmp_path,
        {},
        live_url="https://example.com",
        config=QualityDepthConfig(),
        timeout_seconds=120,
    )
    assert result.status == "unavailable"


def test_missing_output_file_degrades_unavailable(tmp_path, monkeypatch) -> None:
    """run_tool exits 0 but writes no LHR file → unavailable (never raises)."""
    monkeypatch.setattr(lh_mod, "resolve_tool", lambda *a, **k: Path("/x/lighthouse"))
    monkeypatch.setattr(lh_mod, "run_tool", lambda *a, **k: _ok())
    result = lh_mod.collect_lighthouse(
        tmp_path,
        {},
        live_url="https://example.com",
        config=QualityDepthConfig(),
        timeout_seconds=120,
    )
    assert result.status == "unavailable"


def test_collect_lighthouse_exported_on_package() -> None:
    """collect_lighthouse is exported on the package namespace (degrade-path gate)."""
    from repo_audit.adapters import quality_depth as qd

    assert hasattr(qd, "collect_lighthouse")


def test_lighthouse_module_has_no_import_subprocess() -> None:
    """All subprocess goes through run_tool — no direct subprocess import."""
    src = Path(lh_mod.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in src
