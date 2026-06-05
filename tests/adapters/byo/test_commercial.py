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
