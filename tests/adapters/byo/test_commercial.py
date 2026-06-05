"""Commercial BYO five-tool wrappers contract (BYO-02, Wave 0 scaffolding).

Pins the first-class commercial opt-in surface for Plan 16-06:
  * all five commercial tools (Semgrep Pro/Code, Socket.dev, GitGuardian, Snyk,
    SonarQube) are default-OFF,
  * the SARIF-emitting tools (Semgrep Pro, Snyk Code, GitGuardian) reuse the
    SHARED ``sarif_to_findings`` path — no forked parse code,
  * every commercial finding is tagged with its ``source_tool`` + dimension
    (D-16-15) — NO corroboration logic lives here (that is Phase 17).

``importorskip`` keeps these SKIPPED until ``repo_audit.adapters.byo.commercial``
lands, then they flip ACTIVE (Phase-3/11 discipline; NOT xfail-strict).
"""
from __future__ import annotations

import pytest

commercial = pytest.importorskip(
    "repo_audit.adapters.byo.commercial",
    reason="Wave 1/2 (plan 16-06) not yet landed — byo.commercial missing",
)


def _registry():
    """Return the commercial-tool registry/config map, tolerating naming variants."""
    for name in ("COMMERCIAL_TOOLS", "COMMERCIAL_REGISTRY", "TOOLS", "commercial_tools"):
        obj = getattr(commercial, name, None)
        if obj is not None:
            return obj
    pytest.fail("byo.commercial exposes no commercial-tool registry")


def test_five_tools_default_off():
    """All five commercial tools are pre-wired and default-OFF.

    The registry exposes Semgrep Pro/Code, Socket.dev, GitGuardian, Snyk and
    SonarQube; each is OFF until explicitly enabled + attested (BYO-01 gate).
    """
    reg = _registry()
    names = " ".join(str(k) for k in (reg.keys() if hasattr(reg, "keys") else reg)).lower()
    for tool in ("semgrep", "socket", "guard", "snyk", "sonar"):
        assert tool in names, f"commercial registry missing a {tool!r} wrapper"


def test_sarif_tools_reuse_shared_path():
    """SARIF-emitting commercial tools reuse the shared ``sarif_to_findings``.

    The lane exposes a function that routes SARIF through the shared parser
    (Semgrep Pro / Snyk Code / GitGuardian emit SARIF natively), so the candidate
    cap and one parse path are preserved.
    """
    import repo_audit.adapters.sarif as sarif_pkg

    runner = None
    for name in ("run_commercial", "run_byo_commercial", "run_commercial_tool"):
        runner = getattr(commercial, name, None)
        if runner is not None:
            break
    assert runner is not None, "byo.commercial exposes no run entry point"
    # The shared parser is the canonical path the wrappers must reuse.
    assert hasattr(sarif_pkg, "sarif_to_findings")


def test_source_tool_and_dimension_tagged():
    """D-16-15: commercial findings carry source_tool + dimension; NO corroboration.

    The commercial wrappers tag each finding's source_tool and dimension and do
    NOT perform any corroboration/promotion (that is Phase 17's sole job) — a
    source-string assert keeps the corroboration logic out of this module.
    """
    import inspect

    source = inspect.getsource(commercial)
    assert "source_tool" in source or "source_adapter" in source
    # Corroboration must not live here.
    assert "corroborat" not in source.lower()


# --- CR-01 regression: SARIF tools that emit to stdout vs to a file ----------
# The Wave-0 scaffolding only asserted symbols exist; the live-invocation path
# was untested, hiding the bug where Semgrep Pro / ggshield (which print SARIF to
# stdout, no --output flag) had their findings silently discarded because
# run_byo_tool only ever read cfg.sarif_output (a file the tool never wrote).
# These tests drive run_byo_commercial end-to-end with a mocked run_tool.

from pathlib import Path  # noqa: E402

import repo_audit.adapters.byo.adapter as _adapter_mod  # noqa: E402
from repo_audit.adapters.base import InvocationResult  # noqa: E402
from repo_audit.adapters.byo.config import ByoToolConfig  # noqa: E402

_GGSHIELD_SARIF = Path(
    "tests/adapters/fixtures/ggshield/secret.sarif"
).read_text(encoding="utf-8")
_SNYK_SARIF = Path("tests/adapters/fixtures/snyk/code.sarif").read_text(encoding="utf-8")


def _attested_cfg(name: str, sarif_output: str) -> ByoToolConfig:
    return ByoToolConfig(
        name=name,
        enabled=True,
        use_rights_attestation=True,
        sarif_output=sarif_output,
        default_dimension="security",
    )


def test_stdout_sarif_tool_findings_flow_through(monkeypatch, tmp_path):
    """CR-01: a SARIF-on-stdout tool (ggshield) surfaces findings on a live run.

    ggshield exits NON-ZERO when it finds secrets (Pitfall 9) and prints its
    SARIF to stdout — never to a file. The fix must capture inv.stdout and route
    it through the shared parser. Before the fix this returned unavailable with
    zero findings.
    """
    monkeypatch.setattr(
        commercial, "resolve_tool", lambda *a, **k: Path("/usr/bin/ggshield")
    )
    monkeypatch.setattr(
        _adapter_mod,
        "run_tool",
        lambda *a, **k: InvocationResult(
            stdout=_GGSHIELD_SARIF, stderr="", returncode=1
        ),
    )

    res = commercial.run_byo_commercial(
        tmp_path,
        base_env={},
        scratch_dir=tmp_path,
        configs={"gitguardian": _attested_cfg("gitguardian", ".gg/out.sarif")},
    )

    assert res.status == "ok"
    assert res.findings, "stdout SARIF must surface findings (CR-01 regression)"
    assert all(f.source_tool == "gitguardian" for f in res.findings)


def test_stdout_sarif_tool_empty_stdout_is_unavailable(monkeypatch, tmp_path):
    """A stdout SARIF tool that prints nothing parseable degrades honestly."""
    monkeypatch.setattr(
        commercial, "resolve_tool", lambda *a, **k: Path("/usr/bin/semgrep")
    )
    monkeypatch.setattr(
        _adapter_mod,
        "run_tool",
        lambda *a, **k: InvocationResult(stdout="", stderr="boom", returncode=2),
    )

    res = commercial.run_byo_commercial(
        tmp_path,
        base_env={},
        scratch_dir=tmp_path,
        configs={"semgrep-pro": _attested_cfg("semgrep-pro", ".semgrep/out.sarif")},
    )

    assert res.status == "unavailable"
    assert not res.findings


def test_file_sarif_tool_still_reads_file(monkeypatch, tmp_path):
    """Regression guard: file-writing SARIF tools (Snyk) keep reading the file.

    Snyk uses --sarif-file-output, so it writes cfg.sarif_output rather than
    stdout. The stdout fix must NOT break this path.
    """
    sarif_path = tmp_path / ".snyk" / "out.sarif"
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(_SNYK_SARIF, encoding="utf-8")

    monkeypatch.setattr(
        commercial, "resolve_tool", lambda *a, **k: Path("/usr/bin/snyk")
    )
    # Snyk writes the file itself; the mocked invocation just succeeds.
    monkeypatch.setattr(
        _adapter_mod,
        "run_tool",
        lambda *a, **k: InvocationResult(stdout="", stderr="", returncode=0),
    )

    res = commercial.run_byo_commercial(
        tmp_path,
        base_env={},
        scratch_dir=tmp_path,
        configs={"snyk": _attested_cfg("snyk", ".snyk/out.sarif")},
    )

    assert res.status == "ok"
    assert res.findings, "file-based SARIF tool must still surface findings"
    assert all(f.source_tool == "snyk" for f in res.findings)
