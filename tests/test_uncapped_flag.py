"""UNCAPPED-01 — the --uncapped cap-removal plumbing, asserted DIRECTLY.

The project's --no-agent suite cannot exercise the live agent/critic path
(no live ClaudeSDKClient in unit tests), so this module pins the cap-removal
behavior at the plumbing layer instead:

  1. Resolution helpers (uncap_internal_threshold / uncap_sdk_budget) — the
     single source of truth for the uncapped sentinels.
  2. build_options budgets — None when uncapped, 20 / 3.00 by default.
  3. build_critic_options budgets — None when uncapped, 6 / 1.50 by default.
  4. Signature plumbing — every library entry point accepts uncapped=False.
  5. CLI flag + --agent-budget interaction — the flag reaches run_scan, and
     --uncapped is accepted ALONGSIDE --agent-budget (precedence enforced
     inside run_scan).
  6. --uncapped wins at the resolution layer — the agent token cap resolves
     to inf regardless of any AGENT_DEFAULTS budget value.

All tests are offline/hermetic (no live SDK). The CLI tests monkeypatch
``repo_audit.cli.run_scan`` with a kwargs-capturing spy.
"""
from __future__ import annotations

import inspect
from datetime import date

import pytest
from typer.testing import CliRunner

pytest.importorskip("claude_agent_sdk", reason="UNCAPPED-01 SDK option plumbing required")

from repo_audit.agent.constants import (  # noqa: E402
    uncap_internal_threshold,
    uncap_sdk_budget,
)

# Capture the REAL run_agent_session at import (collection) time, BEFORE the
# autouse conftest._stub_agent_session fixture monkeypatches the module
# attribute to a hermetic no-op (whose **kwargs signature would hide the real
# uncapped param). The signature-plumbing test asserts against this reference.
_real_run_agent_session = pytest.importorskip(
    "repo_audit.agent.session"
).run_agent_session


# --- 1. helper resolution ------------------------------------------------

@pytest.mark.parametrize(
    "key,default",
    [
        ("agent.max_tokens_per_scan", 150_000),
        ("critic.max_tokens_per_scan", 60_000),
        ("critic.max_wall_clock_seconds", 180),
    ],
)
def test_uncap_internal_threshold(key, default):
    """uncap_internal_threshold → AGENT_DEFAULTS value (capped) / inf (uncapped)."""
    assert uncap_internal_threshold(key, False) == default
    assert uncap_internal_threshold(key, True) == float("inf")


@pytest.mark.parametrize(
    "key,default",
    [
        ("agent.max_turns", 20),
        ("agent.max_budget_usd", 3.00),
        ("critic.max_turns", 6),
        ("critic.max_budget_usd", 1.50),
    ],
)
def test_uncap_sdk_budget(key, default):
    """uncap_sdk_budget → AGENT_DEFAULTS value (capped) / None (uncapped)."""
    assert uncap_sdk_budget(key, False) == default
    assert uncap_sdk_budget(key, True) is None


# --- 2. build_options budgets --------------------------------------------

def _build_agent_options(tmp_path, *, uncapped: bool):
    import repo_audit.adapters.typescript as _ts  # noqa: F401 — register adapter
    from repo_audit.agent.options import build_options
    from repo_audit.agent.tools import (
        available_tools_for_prompt,
        build_mcp_server,
    )
    from repo_audit.schema.detection import DetectionResult, StackProfile
    from repo_audit.schema.report import ReportMeta
    from repo_audit.schema.scope_ledger import ScopeLedger

    detection = DetectionResult(stacks=[
        StackProfile(stack="typescript-node", root_dir=tmp_path, manifests=[],
                     confidence=0.95),
    ])
    meta = ReportMeta(
        repo_slug="test", commit_sha="abc", scan_date=date.today(),
        tool_version="0.1.0",
    )
    server = build_mcp_server(findings=[], scope_ledger=ScopeLedger(), meta=meta)
    return build_options(
        detection=detection,
        repo_name="test",
        partial=False,
        mcp_server=server,
        available_tools_for_prompt=available_tools_for_prompt(),
        uncapped=uncapped,
    )


def test_build_options_uncapped_removes_sdk_budgets(tmp_path):
    """build_options(uncapped=True) → max_turns is None AND max_budget_usd is None."""
    options = _build_agent_options(tmp_path, uncapped=True)
    assert options.max_turns is None
    assert options.max_budget_usd is None


def test_build_options_default_keeps_sdk_budgets(tmp_path):
    """Default (uncapped=False) → max_turns == 20 AND max_budget_usd == 3.00 (unchanged)."""
    options = _build_agent_options(tmp_path, uncapped=False)
    assert options.max_turns == 20
    assert options.max_budget_usd == 3.00


# --- 3. build_critic_options budgets -------------------------------------

def _build_critic_options(*, uncapped: bool):
    from repo_audit.verification.critic import (
        build_critic_mcp_server,
        build_critic_options,
    )

    server = build_critic_mcp_server()
    return build_critic_options(
        mcp_server=server, system_prompt="critic system prompt", uncapped=uncapped
    )


def test_build_critic_options_uncapped_removes_sdk_budgets():
    """build_critic_options(uncapped=True) → max_turns/max_budget_usd are None."""
    options = _build_critic_options(uncapped=True)
    assert options.max_turns is None
    assert options.max_budget_usd is None


def test_build_critic_options_default_keeps_sdk_budgets():
    """Default → critic max_turns == 6 AND max_budget_usd == 1.50 (unchanged)."""
    options = _build_critic_options(uncapped=False)
    assert options.max_turns == 6
    assert options.max_budget_usd == 1.50


# --- 4. signature plumbing -----------------------------------------------

def test_uncapped_threaded_through_library_signatures():
    """Every library entry point accepts uncapped (default False) — thread-through."""
    from repo_audit.agent.options import build_options
    from repo_audit.orchestration.scan_runner import run_scan
    from repo_audit.verification.critic import run_critic_session
    from repo_audit.verification.stage import run_verification

    for fn in (
        build_options,
        _real_run_agent_session,  # captured pre-stub (conftest patches the live attr)
        run_critic_session,
        run_verification,
        run_scan,
    ):
        params = inspect.signature(fn).parameters
        assert "uncapped" in params, f"{fn.__name__} missing uncapped param"
        assert params["uncapped"].default is False, (
            f"{fn.__name__} uncapped default must be False"
        )


# --- 5. CLI flag + --agent-budget interaction ----------------------------

class _FakeScanResult:
    """Minimal stand-in for ScanResult — only the fields the CLI reads."""

    def __init__(self, tmp_path):
        self.scan_report = None
        self.md_path = tmp_path / "report.md"
        self.json_path = tmp_path / "report.json"
        self.rc = 0
        self.agent_status = None
        self.offenders = []
        self.prior_sidecar = None


def _spy_run_scan(captured, tmp_path):
    def _spy(repo_path, **kwargs):
        captured.append(kwargs)
        return _FakeScanResult(tmp_path)

    return _spy


def test_cli_uncapped_flag_reaches_run_scan(tmp_path, monkeypatch):
    """repo-audit scan --uncapped → run_scan receives uncapped=True."""
    import repo_audit.cli as cli_mod

    captured: list = []
    monkeypatch.setattr(cli_mod, "run_scan", _spy_run_scan(captured, tmp_path))

    result = CliRunner().invoke(cli_mod.app, ["scan", "--uncapped", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0]["uncapped"] is True


def test_cli_uncapped_wins_alongside_agent_budget(tmp_path, monkeypatch):
    """repo-audit scan --uncapped --agent-budget N → run_scan STILL receives uncapped=True.

    The flag is accepted alongside the budget; precedence (budget ignored) is
    enforced INSIDE run_scan (covered deterministically below).
    """
    import repo_audit.cli as cli_mod

    captured: list = []
    monkeypatch.setattr(cli_mod, "run_scan", _spy_run_scan(captured, tmp_path))

    result = CliRunner().invoke(
        cli_mod.app, ["scan", "--uncapped", "--agent-budget", "99999", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0]["uncapped"] is True
    assert captured[0]["agent_budget"] == 99999


def test_cli_default_passes_uncapped_false(tmp_path, monkeypatch):
    """repo-audit scan (no flag) → run_scan receives uncapped=False (default unchanged)."""
    import repo_audit.cli as cli_mod

    captured: list = []
    monkeypatch.setattr(cli_mod, "run_scan", _spy_run_scan(captured, tmp_path))

    result = CliRunner().invoke(cli_mod.app, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    assert captured[0]["uncapped"] is False


# --- 6. --uncapped wins over --agent-budget at the resolution layer -------

def test_uncapped_token_cap_independent_of_budget_mutation():
    """With uncapped=True the agent token cap resolves to inf regardless of budget.

    Documents the precedence deterministically: even if --agent-budget had
    mutated AGENT_DEFAULTS, the uncapped resolution short-circuits to inf and
    never reads the (possibly mutated) value.
    """
    from repo_audit.agent.constants import AGENT_DEFAULTS

    original = AGENT_DEFAULTS["agent.max_tokens_per_scan"]
    try:
        AGENT_DEFAULTS["agent.max_tokens_per_scan"] = 99999  # simulate a budget mutation
        assert uncap_internal_threshold("agent.max_tokens_per_scan", True) == float("inf")
        # And the capped path still honors the (mutated) value — no inf leakage.
        assert uncap_internal_threshold("agent.max_tokens_per_scan", False) == 99999
    finally:
        AGENT_DEFAULTS["agent.max_tokens_per_scan"] = original
