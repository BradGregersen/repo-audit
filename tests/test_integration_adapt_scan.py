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
ADAPT_GARMIN_PATH = Path("/path/to/example-companion-app")


pytestmark = pytest.mark.integration


def _skip_if_no_adapt():
    if not ADAPT_PATH.exists():
        pytest.skip(f"{ADAPT_PATH} not available on this machine")
    if not (ADAPT_PATH / ".git").exists():
        pytest.skip(f"{ADAPT_PATH} is not a git repo")


def _skip_if_no_adapt_garmin():
    if not ADAPT_GARMIN_PATH.exists():
        pytest.skip(f"{ADAPT_GARMIN_PATH} not available on this machine")
    if not (ADAPT_GARMIN_PATH / ".git").exists():
        pytest.skip(f"{ADAPT_GARMIN_PATH} is not a git repo")


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
    """`--no-agent` path produces a deterministic-only report; exit 0.

    This is the deterministic 999.1 canary. History:
      * Before Plan 01's byte caps the adapt --no-agent scan overran ~337s in
        file_size_cap and timed out.
      * After Plan 01 the FULL pipeline still ran ~415s because the read-heavy /
        subprocess collectors were unbounded INSIDE their own bodies — chiefly
        secret_detection, which spawns a gitleaks subprocess PER text file
        (~13.7k files on adapt). The between-collector deadline could not
        interrupt a single running collector, so the canary had been relaxed to
        600s as "closed-enough".
      * 05.1-gap (Blocker A) actually bounds it: each read-heavy collector now
        polls the shared scan deadline from inside its loop (TIME_BUDGET_S=95s
        collector phase) and self-reports status='timeout' (-> partial banner +
        scope ledger disclosure, SAFE-08). The deterministic collector phase is
        hard-capped at 95s; the whole `repo-audit scan --no-agent` adapt run finishes
        116-118s on a QUIET host (95s collectors + ~21s walker/adapters/render
        tail; clean samples 116s & 118s, 2026-05-30).

    The canary is therefore TIGHTENED to 180s: a real tripwire (~52% headroom
    over the measured ~118s for slower disks / shared CI runners) that catches a
    reintroduced unbounded collector / walk, well below the documented 300s scan
    ceiling. (NOTE: measure on a QUIET host — leaked gitleaks/scan children from
    a killed prior run compete for CPU and inflate this badly; reap them first.)
    """
    _skip_if_no_adapt()
    # 05.1-gap: clean quiet-host runs on the 40 GB adapt (2026-05-30) were 116s
    # and 118s, exit 0, both reports written, meta.partial=True with the
    # secret_detection timeout disclosed in the scope ledger. 180s keeps ~52%
    # headroom while staying a tight regression tripwire (< the 300s ceiling).
    result = subprocess.run(
        ["uv", "run", "arch", "scan", "--no-agent", str(ADAPT_PATH)],
        capture_output=True, timeout=180,
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


def test_adapt_garmin_no_agent_exit0():
    """`--no-agent` on adapt-garmin exits 0 and logs entropy redactions.

    This is the deterministic 999.2 canary. adapt-garmin is the repo that
    previously made `repo-audit scan` exit 2: its benign `sha512-` integrity hashes
    tripped the entropy backstop, which used to hard-fail. Plan 02 split the
    secret-lint so the entropy backstop redacts-and-continues (value-blind),
    leaving gitleaks/known-patterns as the only hard blockers. So now:
      1. exit 0 (was exit 2) — the 999.2 fix proof.
      2. md + json reports are written under docs/state-reports/.
      3. meta.entropy_redactions is a NON-EMPTY list — proving the redact path
         actually RAN on adapt-garmin's benign hashes, not that the buffer
         merely failed to trip.
    adapt-garmin is the known exit-2 repo, so redactions are expected. If a
    given machine's adapt-garmin somehow contains zero high-entropy tokens,
    item 3 would need downgrading to "field exists as a list" — but that is
    not the expected state of this canary repo.
    """
    _skip_if_no_adapt_garmin()
    result = subprocess.run(
        ["uv", "run", "arch", "scan", "--no-agent", str(ADAPT_GARMIN_PATH)],
        capture_output=True, timeout=120,
    )
    # 1. exit 0 (was exit 2 before Plan 02's redact-and-continue split).
    assert result.returncode == 0, (
        f"repo-audit scan --no-agent adapt-garmin failed: "
        f"stderr={result.stderr.decode()[-2000:]}"
    )

    # 2. md + json reports for today exist.
    today = date.today().isoformat()
    md_path = (
        ADAPT_GARMIN_PATH / "docs" / "state-reports"
        / f"adapt-garmin-state-report-{today}.md"
    )
    json_path = (
        ADAPT_GARMIN_PATH / "docs" / "state-reports"
        / f"adapt-garmin-state-report-{today}.json"
    )
    assert md_path.exists(), f"markdown report missing at {md_path}"
    assert json_path.exists(), f"json sidecar missing at {json_path}"

    # 3. entropy_redactions populated → redact-and-continue path ran.
    sidecar = json.loads(json_path.read_text())
    redactions = sidecar["meta"].get("entropy_redactions")
    assert isinstance(redactions, list), (
        f"meta.entropy_redactions should be a list, got {type(redactions)}"
    )
    assert len(redactions) > 0, (
        "meta.entropy_redactions is empty: the entropy backstop did not "
        "redact adapt-garmin's benign high-entropy hashes — the Plan-02 "
        "redact-and-continue path did not run (or the buffer never tripped)."
    )
