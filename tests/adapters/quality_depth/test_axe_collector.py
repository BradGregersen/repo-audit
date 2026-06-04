"""A11Y-01 runtime tier (Phase 15, Plan 02, Task 2) — collect_axe degrade + run.

``collect_axe`` is the live-URL-gated, never-raising collector:

  * GATE 1 (SAFE-08 / T-15-03): no ``live_url`` → ``status="unavailable"``
    WITHOUT invoking any binary (zero network egress — the run_tool spy must
    record ZERO calls).
  * GATE 2: ``resolve_tool("axe") is None`` → ``status="unavailable"``.
  * GATE 3: a successful ``run_tool`` + a written results file → Findings.
  * GATE 4: ``TIMED_OUT`` → ``status="timeout"``; a non-zero exit → unavailable.

All subprocess work goes through the shared ``run_tool`` seam; ``axe.py`` never
imports ``subprocess`` directly.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip(
    "repo_audit.adapters.quality_depth.axe",
    reason="Wave 1 (Plan 02) not yet landed — quality_depth.axe missing",
)

from repo_audit.adapters.base import InvocationResult  # noqa: E402
from repo_audit.adapters.quality_depth import axe as axe_mod  # noqa: E402
from repo_audit.adapters.quality_depth.axe import collect_axe  # noqa: E402
from repo_audit.adapters.toolops import TIMED_OUT  # noqa: E402


def test_no_live_url_unavailable_zero_egress(tmp_path: Path, monkeypatch) -> None:
    """No live_url → unavailable; run_tool is NEVER called (SAFE-08 no-egress)."""
    calls: list = []

    def _spy(*args, **kwargs):  # pragma: no cover - must never run
        calls.append((args, kwargs))
        raise AssertionError("run_tool must NOT be called when live_url is None")

    monkeypatch.setattr(axe_mod, "run_tool", _spy)
    # resolve_tool must also never be reached before the URL gate.
    monkeypatch.setattr(
        axe_mod,
        "resolve_tool",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("resolve_tool reached before the live_url gate")
        ),
    )

    result = collect_axe(tmp_path, {}, live_url=None, timeout_seconds=120)
    assert result.status == "unavailable"
    assert result.findings == []
    assert calls == []


def test_binary_absent_unavailable(tmp_path: Path, monkeypatch) -> None:
    """resolve_tool None → unavailable; run_tool not invoked."""
    calls: list = []
    monkeypatch.setattr(axe_mod, "resolve_tool", lambda *a, **k: None)
    monkeypatch.setattr(
        axe_mod, "run_tool", lambda *a, **k: calls.append(1)
    )
    result = collect_axe(
        tmp_path, {}, live_url="https://example.com", timeout_seconds=120
    )
    assert result.status == "unavailable"
    assert calls == []


def test_success_path_maps_findings(tmp_path: Path, monkeypatch) -> None:
    """A successful run that writes the results file → mapped Findings."""
    fixture = (
        Path(__file__).parent / "fixtures" / "axe_results.json"
    ).read_text(encoding="utf-8")

    monkeypatch.setattr(
        axe_mod, "resolve_tool", lambda *a, **k: Path("/usr/bin/axe")
    )

    def _fake_run(argv, *, env, cwd, timeout_seconds):
        # The collector passes `--save <out_json>`; write the fixture there so
        # the collector reads the FILE (never stdout).
        out_json = Path(argv[argv.index("--save") + 1])
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(fixture, encoding="utf-8")
        return InvocationResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(axe_mod, "run_tool", _fake_run)

    result = collect_axe(
        tmp_path, {}, live_url="https://example.com", timeout_seconds=120
    )
    assert result.status == "ok"
    assert len(result.findings) == 2
    assert all(f.evidence_type == "runtime" for f in result.findings)


def test_timeout_maps_to_timeout(tmp_path: Path, monkeypatch) -> None:
    """run_tool TIMED_OUT sentinel → status=timeout."""
    monkeypatch.setattr(
        axe_mod, "resolve_tool", lambda *a, **k: Path("/usr/bin/axe")
    )
    monkeypatch.setattr(
        axe_mod,
        "run_tool",
        lambda *a, **k: InvocationResult(returncode=TIMED_OUT),
    )
    result = collect_axe(
        tmp_path, {}, live_url="https://example.com", timeout_seconds=1
    )
    assert result.status == "timeout"


def test_nonzero_exit_unavailable(tmp_path: Path, monkeypatch) -> None:
    """A non-zero/non-sentinel exit (e.g. Chrome sandbox failure) → unavailable."""
    monkeypatch.setattr(
        axe_mod, "resolve_tool", lambda *a, **k: Path("/usr/bin/axe")
    )
    monkeypatch.setattr(
        axe_mod,
        "run_tool",
        lambda *a, **k: InvocationResult(returncode=1, stderr="chrome sandbox"),
    )
    result = collect_axe(
        tmp_path, {}, live_url="https://example.com", timeout_seconds=120
    )
    assert result.status == "unavailable"


def test_success_but_no_file_unavailable(tmp_path: Path, monkeypatch) -> None:
    """Exit 0 but no results file written → unavailable (never raises)."""
    monkeypatch.setattr(
        axe_mod, "resolve_tool", lambda *a, **k: Path("/usr/bin/axe")
    )
    monkeypatch.setattr(
        axe_mod, "run_tool", lambda *a, **k: InvocationResult(returncode=0)
    )
    result = collect_axe(
        tmp_path, {}, live_url="https://example.com", timeout_seconds=120
    )
    assert result.status == "unavailable"


def test_no_subprocess_import() -> None:
    """Source assertion: axe.py routes ALL subprocess work through run_tool."""
    src = Path(axe_mod.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in src


def test_collect_axe_exported_on_package() -> None:
    """collect_axe is reachable on the package namespace (degrade-path gate)."""
    import repo_audit.adapters.quality_depth as qd

    assert hasattr(qd, "collect_axe")
