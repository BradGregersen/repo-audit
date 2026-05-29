"""Wave 0 stub for AGENT CLI flags (Plan 04-09).

The CLI already exists, so there is no module to importorskip. Instead this
module guards on the *presence of the --no-agent flag* in `repo-audit scan --help`:
the flag lands in Plan 04-09, so until then the whole module SKIPs cleanly
and flips ACTIVE automatically once the flag is wired. This mirrors the
Phase 3 importorskip discipline for a CLI-extension contract (the symbol
being gated on is a CLI flag, not an importable module).

Do NOT replace the skip guard or the `pass` bodies in this Wave 0 task —
Plan 04-09 owns the CLI extension; this task only pins contract names.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_no_agent_flag_present       (Plan 04-09 — --no-agent flag documented in help)
- test_agent_budget_flag_present   (Plan 04-09 — --agent-budget flag documented in help)
- test_no_agent_skips_agent_session(Plan 04-09 — --no-agent → run_agent_session not called)
"""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

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
    pass


def test_agent_budget_flag_present():
    """Plan 04-09: the --agent-budget flag is documented in `repo-audit scan --help`."""
    pass


def test_no_agent_skips_agent_session():
    """Plan 04-09: --no-agent set → run_agent_session is not called."""
    pass
