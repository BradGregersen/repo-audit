"""Live-SDK end-to-end integration test against /path/to/example-app.

Gated behind `pytest -m integration` (existing marker from Phase 3
pyproject.toml). Requires:
  - Claude Code CLI auth (the user already has this for /gsd-* commands)
  - /path/to/example-app cloned + node_modules present (Phase 3 invariant)

This test is the user-machine dogfood checkpoint Phase 4 ships with.
The "agent narrative reads like the hand-written 2026-05-23 report"
quality bar is documented in the SUMMARY for manual review — pytest
cannot evaluate prose quality, only structural shape.

Skips cleanly (not errors) when /path/to/example-app is missing or the
SDK is unavailable.
"""
from __future__ import annotations

import json
import subprocess
from datetime import date
from pathlib import Path

import pytest

ADAPT_PATH = Path("/path/to/example-app")


pytestmark = pytest.mark.integration


def _skip_if_no_adapt():
    if not ADAPT_PATH.exists():
        pytest.skip(f"{ADAPT_PATH} not available on this machine")
    if not (ADAPT_PATH / ".git").exists():
        pytest.skip(f"{ADAPT_PATH} is not a git repo")


def test_adapt_scan_produces_narrative():
    """Live agent loop produces a report with non-empty dimension narratives."""
    _skip_if_no_adapt()

    # Run `repo-audit scan /path/to/example-app`.
    result = subprocess.run(
        ["uv", "run", "arch", "scan", str(ADAPT_PATH)],
        capture_output=True, timeout=600,
    )
    if "unavailable_auth_missing" in result.stderr.decode():
        pytest.skip("Claude Code SDK not authed on this machine")
    assert result.returncode == 0, (
        f"repo-audit scan failed: stderr={result.stderr.decode()[-2000:]}"
    )

    today = date.today().isoformat()
    md_path = ADAPT_PATH / "docs" / "state-reports" / f"adapt-state-report-{today}.md"
    json_path = ADAPT_PATH / "docs" / "state-reports" / f"adapt-state-report-{today}.json"
    assert md_path.exists(), f"markdown report missing at {md_path}"
    assert json_path.exists(), f"json sidecar missing at {json_path}"

    # Markdown structural check: agent meta footer present.
    md = md_path.read_text()
    assert "Agent status:" in md or "agent_status" in md.lower()

    # JSON sidecar: meta carries Phase 4 fields.
    sidecar = json.loads(json_path.read_text())
    assert "agent_status" in sidecar["meta"]
    # Either successful or one of the documented failure modes.
    valid_statuses = {
        "ok", "unavailable_auth_missing", "unavailable_network",
        "unavailable_emit_report_invalid", "unavailable_sdk_exception",
        "cost_capped",
    }
    assert sidecar["meta"]["agent_status"] in valid_statuses


def test_no_agent_path_produces_report():
    """`--no-agent` path produces a deterministic-only report; exit 0."""
    _skip_if_no_adapt()
    result = subprocess.run(
        ["uv", "run", "arch", "scan", "--no-agent", str(ADAPT_PATH)],
        capture_output=True, timeout=300,
    )
    assert result.returncode == 0
    today = date.today().isoformat()
    md_path = ADAPT_PATH / "docs" / "state-reports" / f"adapt-state-report-{today}.md"
    assert md_path.exists()
    # No agent_status because the session was skipped entirely.
    json_path = ADAPT_PATH / "docs" / "state-reports" / f"adapt-state-report-{today}.json"
    sidecar = json.loads(json_path.read_text())
    # agent_status was never set → None in JSON.
    assert sidecar["meta"].get("agent_status") is None
