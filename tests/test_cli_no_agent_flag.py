"""AGENT CLI flags + agent-session wiring (Plan 04-09).

The CLI already exists, so there is no module to importorskip. Instead this
module guards on the *presence of the --no-agent flag* in `repo-audit scan --help`:
the flag lands in Plan 04-09, so until then the whole module SKIPs cleanly
and flips ACTIVE automatically once the flag is wired. This mirrors the
Phase 3 importorskip discipline for a CLI-extension contract (the symbol
being gated on is a CLI flag, not an importable module).

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_no_agent_flag_present       (Plan 04-09 — --no-agent flag documented in help)
- test_agent_budget_flag_present   (Plan 04-09 — --agent-budget flag documented in help)
- test_no_agent_skips_agent_session(Plan 04-09 — --no-agent → run_agent_session not called)
"""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

import repo_audit.agent.session as session_mod
from repo_audit.agent.constants import AGENT_DEFAULTS, get_threshold
from repo_audit.cli import app


def _no_agent_flag_landed() -> bool:
    """True once Plan 04-09 wires the --no-agent flag into `repo-audit scan`."""
    result = CliRunner().invoke(app, ["scan", "--help"])
    return "--no-agent" in result.output


pytestmark = pytest.mark.skipif(
    not _no_agent_flag_landed(),
    reason="Plan 04-09 has not landed yet (--no-agent absent from scan --help) — Wave 0 stub.",
)


def test_no_agent_flag_present():
    """Plan 04-09: the --no-agent flag is documented in `repo-audit scan --help`."""
    result = CliRunner().invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--no-agent" in result.output


def test_agent_budget_flag_present():
    """Plan 04-09: the --agent-budget flag is documented in `repo-audit scan --help`."""
    result = CliRunner().invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--agent-budget" in result.output


def test_no_agent_skips_agent_session(tmp_path, monkeypatch):
    """Plan 04-09: --no-agent set → run_agent_session is NEVER called; exit 0."""
    calls: list = []

    async def _spy_run_agent_session(**kwargs):  # pragma: no cover — must not run
        calls.append(kwargs)
        return None, kwargs["meta"]

    monkeypatch.setattr(session_mod, "run_agent_session", _spy_run_agent_session)

    result = CliRunner().invoke(app, ["scan", "--no-agent", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert calls == [], "run_agent_session was called despite --no-agent"


def test_default_invokes_agent_session_once(tmp_path, monkeypatch):
    """Plan 04-09: default (no --no-agent) → run_agent_session called exactly once."""
    calls: list = []

    async def _spy_run_agent_session(**kwargs):
        calls.append(kwargs)
        return None, kwargs["meta"]

    monkeypatch.setattr(session_mod, "run_agent_session", _spy_run_agent_session)

    result = CliRunner().invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert len(calls) == 1, "run_agent_session should run exactly once on the default path"


def test_agent_budget_overrides_token_cap(tmp_path, monkeypatch):
    """Plan 04-09: --agent-budget N → get_threshold('agent.max_tokens_per_scan') == N."""
    observed: list = []
    original = AGENT_DEFAULTS["agent.max_tokens_per_scan"]

    async def _spy_run_agent_session(**kwargs):
        observed.append(get_threshold("agent.max_tokens_per_scan"))
        return None, kwargs["meta"]

    monkeypatch.setattr(session_mod, "run_agent_session", _spy_run_agent_session)

    try:
        result = CliRunner().invoke(
            app, ["scan", "--agent-budget", "5000", str(tmp_path)]
        )
        assert result.exit_code == 0, result.output
        assert observed == [5000]
    finally:
        AGENT_DEFAULTS["agent.max_tokens_per_scan"] = original
