"""ARCH-02 duplication collector contract (Plan 14-03, Wave-2).

SKIPPED until ``architecture.duplication`` (jscpd) lands. Pins the collector
mechanics distinct from the pure JSON map (test_jscpd_json.py): the ``--ignore``
argv is built from DEFAULT_SKIP_DIRS (Pitfall 7); the report is read from the
FILE ``<output>/jscpd-report.json`` (Pitfall 2), NOT stdout; and the duplication
floor is overridable via ``.repo-audit.yaml`` (SC4).

run_tool is stubbed to SIMULATE jscpd writing ``jscpd-report.json`` into the
``--output`` dir extracted from argv (the test_iac.py ``_stub_run_writes``
idiom), so the parse path runs hermetically regardless of whether jscpd is
installed on the test host.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

duplication = pytest.importorskip(
    "repo_audit.adapters.architecture.duplication",
    reason="Wave 2 (Plan 03) not yet landed — architecture.duplication missing",
)

_FAKE_BIN = "/usr/bin/__jscpd__"


def _stub_resolve(monkeypatch, binary=_FAKE_BIN):
    monkeypatch.setattr(
        duplication, "resolve_tool", lambda *a, **k: binary, raising=False
    )


def _stub_run_writes(monkeypatch, report_dict, *, returncode=0, captured=None):
    """Stub run_tool so jscpd writes jscpd-report.json into the --output dir.

    Mirrors jscpd's real behavior: the JSON report lands in the ``--output``
    directory as ``jscpd-report.json`` (Pitfall 2). The stub extracts that dir
    from the argv, writes the fixture there, and records the argv if requested.
    """
    from repo_audit.adapters import toolops

    def _run(argv, *, env, cwd, timeout_seconds):
        if captured is not None:
            captured["argv"] = list(argv)
        out_dir = Path(argv[argv.index("--output") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "jscpd-report.json").write_text(
            json.dumps(report_dict), encoding="utf-8"
        )
        return toolops.InvocationResult(
            stdout="banner noise", stderr="", returncode=returncode
        )

    monkeypatch.setattr(duplication, "run_tool", _run, raising=False)


def test_ignore_built_from_default_skip_dirs(
    monkeypatch, fake_js_repo, load_json
) -> None:
    """The --ignore argv is built from DEFAULT_SKIP_DIRS (Pitfall 7)."""
    from repo_audit.walker.skip_dirs import DEFAULT_SKIP_DIRS

    captured: dict = {}
    repo = fake_js_repo(duplicate=True)
    _stub_resolve(monkeypatch)
    _stub_run_writes(monkeypatch, load_json("jscpd"), captured=captured)

    duplication.collect_jscpd(repo, {})

    argv = captured["argv"]
    assert "--ignore" in argv
    ignore_val = argv[argv.index("--ignore") + 1]
    # At least one well-known skip dir (e.g. node_modules) appears in the glob.
    assert any(d in ignore_val for d in DEFAULT_SKIP_DIRS)


def test_report_read_from_file_not_stdout(
    monkeypatch, fake_js_repo, load_json
) -> None:
    """The collector parses the written FILE, not stdout (Pitfall 2)."""
    repo = fake_js_repo(duplicate=True)
    _stub_resolve(monkeypatch)
    # stdout is pure banner noise; the real data is only in the written file.
    _stub_run_writes(monkeypatch, load_json("jscpd"))

    result = duplication.collect_jscpd(repo, {})

    # 50% duplication in the fixture → one aggregate finding surfaces.
    assert len(result.findings) == 1
    assert result.status == "ok"


def test_threshold_overridable_via_yaml(
    monkeypatch, fake_js_repo, load_json
) -> None:
    """A high floor_pct override (via .repo-audit.yaml) suppresses the finding."""
    repo = fake_js_repo(duplicate=True)
    # Override the floor to 90%: the fixture's 50% is now BELOW floor → no finding.
    (repo / ".repo-audit.yaml").write_text(
        "architecture:\n  duplication:\n    floor_pct: 90\n", encoding="utf-8"
    )
    _stub_resolve(monkeypatch)
    _stub_run_writes(monkeypatch, load_json("jscpd"))

    result = duplication.collect_jscpd(repo, {})

    assert result.findings == []
    assert result.status == "ok"


def test_jscpd_absent_unavailable(monkeypatch, fake_js_repo) -> None:
    """resolve_tool miss → unavailable, never raises."""
    repo = fake_js_repo(duplicate=True)
    monkeypatch.setattr(
        duplication, "resolve_tool", lambda *a, **k: None, raising=False
    )

    result = duplication.collect_jscpd(repo, {})

    assert result.status == "unavailable"
    assert result.findings == []
