"""KOT-01 — detekt collector contract test (Plan 11-01 Wave 0 scaffolding).

The opening ``pytest.importorskip`` keeps this module SKIPPED until the Wave-1
implementation module ``repo_audit.adapters.kotlin.detekt`` lands, at which
point these assertions activate automatically (the 03-01b
SKIPPED->ACTIVE-on-landing discipline; same pattern as Phase 9's
``test_mobile_mobsfscan.py``). The assertions are REAL (not ``pass``) so the
module fails RED the moment the import resolves but the contract is not yet met.

The detekt SARIF fixture is COPIED from the in-repo Phase-6 source-of-truth
(``tests/adapters/sarif/fixtures/detekt/sample.sarif``, detekt 1.23.8) and
augmented with one ``detekt.potential-bugs.*`` keep-family result so the
noise-floor test (``test_detekt_noise.py``) has both a drop-family and a
keep-family rule to exercise.

Contract pinned (per 11-RESEARCH Pitfalls 4/5/6/7):
    * detekt writes SARIF to a FILE, not stdout (Pitfall 4) — the collector reads
      the SARIF file the invocation produced.
    * detekt exits NON-ZERO when it finds issues (Pitfall 5) — a non-zero exit
      with a parseable SARIF file present is ``status='ok'`` WITH findings, not a
      failure. The collector gates on whether the SARIF PARSES, never on
      returncode.
    * every detekt finding routes to ``source_tool='detekt'``,
      ``dimension='quality'``, ``evidence_type='static'``,
      ``confidence='candidate'`` (Pitfall 6 — ``result.level`` is set, the
      generic parser uses it; warning->major; SCH-04 caps any critical to major
      at candidate).
    * an absent binary / JRE degrades to ``status='unavailable'`` without raising
      (the never-raise scan-completes contract).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

detekt = pytest.importorskip(
    "repo_audit.adapters.kotlin.detekt",
    reason="optional module repo_audit.adapters.kotlin.detekt not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.adapters.base import InvocationResult  # noqa: E402

_SARIF_FIXTURE = Path(__file__).parent / "fixtures" / "detekt-sample.sarif"


def _load_sarif() -> dict:
    return json.loads(_SARIF_FIXTURE.read_text(encoding="utf-8"))


def _collect(collect_fn, repo_path: Path):
    """Invoke the collector's primary entry point (``collect_detekt``).

    Kept as an indirection so the test asserts against whatever the Wave-1
    module names its envelope (``status`` + ``findings`` attributes) — mirrors
    the SCA/mobile collector-result shape.
    """
    return collect_fn(repo_path, env={})


def _patch_detekt(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sarif: dict | None,
    returncode: int,
    resolve_to: Path | None = Path("/vendor/detekt/detekt"),
) -> None:
    """Monkeypatch the detekt module's resolve + run + SARIF-read seam.

    The Wave-1 ``kotlin.detekt`` module is contracted to expose:
        * ``resolve_tool(tool, repo)`` (module-level name, like semgrep) — None
          means the binary/JRE is unavailable.
        * ``run_tool(...)`` (module-level name) — returns an ``InvocationResult``;
          detekt's SARIF lands in a FILE, so stdout is the human summary.
        * a SARIF-read seam (``_read_sarif`` / ``_load_report``) the test points
          at the fixture dict so no real file I/O is needed.

    A ``None`` ``sarif`` simulates "no parseable SARIF produced".
    """
    monkeypatch.setattr(detekt, "resolve_tool", lambda tool, repo, **_kw: resolve_to)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        return InvocationResult(
            stdout="detekt finished.",
            stderr="",
            returncode=returncode,
            command=list(argv),
        )

    monkeypatch.setattr(detekt, "run_tool", fake_run_tool)

    # The collector reads the SARIF the invocation produced. Point whatever
    # read seam the module exposes at the in-memory fixture.
    for seam in ("_read_sarif", "_load_report", "_parse_sarif_file"):
        if hasattr(detekt, seam):
            monkeypatch.setattr(detekt, seam, lambda *a, **k: sarif)
            break


def test_detekt_sarif_roundtrips_via_shared_parser(monkeypatch):
    """A parseable detekt SARIF -> status='ok' with quality/static/candidate findings."""
    sarif = _load_sarif()
    # detekt exits NON-ZERO when it finds issues (Pitfall 5) — that is NOT a failure.
    _patch_detekt(monkeypatch, sarif=sarif, returncode=2)

    result = _collect(detekt.collect_detekt, Path("/repo"))

    assert result.status == "ok"
    assert len(result.findings) >= 1
    for f in result.findings:
        assert f.source_tool == "detekt"
        assert f.dimension == "quality"
        assert f.evidence_type == "static"
        assert f.confidence == "candidate"


def test_detekt_non_zero_exit_is_not_failure(monkeypatch):
    """Non-zero exit WITH a parseable SARIF -> ok + findings (Pitfall 5)."""
    sarif = _load_sarif()
    _patch_detekt(monkeypatch, sarif=sarif, returncode=2)

    result = _collect(detekt.collect_detekt, Path("/repo"))

    assert result.status == "ok"
    assert len(result.findings) >= 1


def test_detekt_argv_runs_a_path_launcher_directly(tmp_path):
    """A ``detekt`` found on PATH is the launcher script; ``java -jar`` cannot run it."""
    launcher = tmp_path / "detekt"
    launcher.write_text('#!/bin/sh\nexec java -jar detekt-cli-all.jar "$@"\n', encoding="utf-8")

    argv = detekt._detekt_argv(
        Path("/usr/bin/java"), launcher, Path("/repo"), tmp_path / "out.sarif", None
    )

    assert argv[0] == str(launcher)
    assert "-jar" not in argv
    assert "--build-upon-default-config" in argv


def test_detekt_argv_runs_a_jar_under_java(tmp_path):
    """The vendored fat jar (no ``.jar`` suffix at ``vendor/detekt/detekt``) runs under ``java -jar``."""
    jar = tmp_path / "detekt"
    jar.write_bytes(b"PK\x03\x04 rest of the archive")

    argv = detekt._detekt_argv(
        Path("/usr/bin/java"), jar, Path("/repo"), tmp_path / "out.sarif", None
    )

    assert argv[:3] == ["/usr/bin/java", "-jar", str(jar)]


def test_detekt_absent_jre_unavailable(monkeypatch):
    """No detekt binary / JRE -> status='unavailable', no raise (scan completes)."""
    _patch_detekt(monkeypatch, sarif=None, returncode=-1, resolve_to=None)

    result = _collect(detekt.collect_detekt, Path("/repo"))

    assert result.status == "unavailable"
    assert result.findings == []
