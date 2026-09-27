"""Live end-to-end integration tests against real repos on the local machine.

Gated behind `pytest -m integration`. Requires:
  - Claude Code CLI auth (for the agent-path test)
  - REPO_AUDIT_LIVE_TARGET set to a multi-stack app checkout (node_modules installed)
  - REPO_AUDIT_LIVE_COMPANION set to a second git repo (for the entropy-redaction canary),
    each test skipping otherwise

pytest cannot evaluate prose quality, only structural shape; narrative quality
is reviewed by hand.

Skips cleanly (not errors) when a target repo is missing or the SDK is
unavailable.
"""
from __future__ import annotations

import json
import subprocess
from datetime import date
from pathlib import Path

import pytest

from tests.live_targets import require_live_companion, require_live_target


pytestmark = pytest.mark.integration


def _written_report_paths(stdout: bytes) -> tuple[Path, Path]:
    """Return the (md, json) report paths THIS scan reported writing.

    ``state_report_paths`` never overwrites a same-day report — it appends
    ``-2``, ``-3``, … instead. Reconstructing ``…-state-report-{today}.json`` by
    hand therefore reads whichever scan ran FIRST today, which in this file is a
    sibling test's run, not this one. ``repo-audit scan`` echoes ``Wrote <path>`` for
    both artifacts; those lines are the only authoritative answer.
    """
    written = [
        Path(line.split("Wrote ", 1)[1].strip())
        for line in stdout.decode(errors="replace").splitlines()
        if line.startswith("Wrote ")
    ]
    md = next((q for q in written if q.suffix == ".md"), None)
    js = next((q for q in written if q.suffix == ".json"), None)
    assert md is not None and js is not None, (
        f"repo-audit scan did not report both report paths; saw: {written}"
    )
    return md, js


def _skip_if_no_example_app() -> Path:
    return require_live_target(git=True)


def _skip_if_no_companion_app() -> Path:
    return require_live_companion()


# timeout: its own subprocess budget is 1200 s; the global 120 s stall-cap would fire on a healthy run.
@pytest.mark.timeout(1260)
def test_example_app_scan_produces_narrative():
    """Live agent loop produces a report with non-empty dimension narratives."""
    target = _skip_if_no_example_app()

    # `repo-audit scan` runs default-on deep tiers: typed detekt (a throwaway-copy
    # gradle build, --typed-detekt defaults True), expo-doctor, and type-coverage.
    # On a multi-stack repo (expo + kotlin-android + typescript-node) all of these
    # fire, so a full agent scan is intentionally heavy: a clean multi-stack
    # `--no-agent` run takes roughly ten minutes, and the agent path adds
    # narrative time on top. 1200 s is a tripwire for an unbounded hang/walk,
    # well above that envelope.
    result = subprocess.run(
        ["uv", "run", "repo-audit", "scan", str(target)],
        capture_output=True, timeout=1200,
    )
    if "unavailable_auth_missing" in result.stderr.decode():
        pytest.skip("Claude Code SDK not authed on this machine")
    assert result.returncode == 0, (
        f"repo-audit scan failed: stderr={result.stderr.decode()[-2000:]}"
    )

    today = date.today().isoformat()
    md_path, json_path = _written_report_paths(result.stdout)
    assert today in md_path.name, f"report is not today's: {md_path}"
    assert md_path.exists(), f"markdown report missing at {md_path}"
    assert json_path.exists(), f"json sidecar missing at {json_path}"

    # Markdown structural check: agent meta footer present.
    md = md_path.read_text()
    assert "Agent status:" in md or "agent_status" in md.lower()

    # JSON sidecar: meta carries the agent fields.
    sidecar = json.loads(json_path.read_text())
    assert "agent_status" in sidecar["meta"]
    # Either successful or one of the documented failure modes.
    valid_statuses = {
        "ok", "unavailable_auth_missing", "unavailable_network",
        "unavailable_emit_report_invalid", "unavailable_sdk_exception",
        "cost_capped",
    }
    assert sidecar["meta"]["agent_status"] in valid_statuses


# timeout: its own subprocess budget is 900 s; the global 120 s stall-cap would fire on a healthy run.
@pytest.mark.timeout(960)
def test_no_agent_path_produces_report():
    """`--no-agent` path produces a deterministic-only report; exit 0.

    This is the deterministic scan-duration canary. History:
      * Before per-file byte caps, a --no-agent scan of a very large monorepo
        overran in file_size_cap and timed out.
      * After the byte caps the full pipeline was still slow because the
        read-heavy / subprocess collectors were unbounded INSIDE their own
        bodies — chiefly secret_detection, which spawned a gitleaks subprocess
        PER text file (thousands of files). The between-collector deadline could
        not interrupt a single running collector.
      * Each read-heavy collector now polls the shared scan deadline from inside
        its loop (TIME_BUDGET_S=95s collector phase) and self-reports
        status='timeout' (-> partial banner + scope ledger disclosure).

    The default-on deep tiers (typed detekt's throwaway-copy gradle classpath
    build, expo-doctor, type-coverage) then made a clean multi-stack
    `--no-agent` run take roughly ten minutes. That cost is intended — the heavy
    tiers are the point — so the canary is 900s: real headroom, still a
    tripwire for a genuinely unbounded collector/walk/hang. (NOTE: measure on a
    QUIET host — leaked gradle/kotlin daemons or gitleaks/scan children from a
    killed prior run compete for CPU and inflate this badly; reap them first.)
    """
    target = _skip_if_no_example_app()
    result = subprocess.run(
        ["uv", "run", "repo-audit", "scan", "--no-agent", str(target)],
        capture_output=True, timeout=900,
    )
    assert result.returncode == 0
    today = date.today().isoformat()
    # Read the sidecar THIS scan wrote. Reconstructing the unsuffixed
    # `…-{today}.json` path reads the agent-path test's report when both run on
    # the same day, and then asserts agent_status is None against a report whose
    # agent DID run — a false failure that says nothing about --no-agent.
    md_path, json_path = _written_report_paths(result.stdout)
    assert today in md_path.name, f"report is not today's: {md_path}"
    assert md_path.exists()
    # No agent_status because the session was skipped entirely.
    sidecar = json.loads(json_path.read_text())
    # agent_status was never set → None in JSON.
    assert sidecar["meta"].get("agent_status") is None


# timeout: its own subprocess budget is 120 s; the global stall-cap needs headroom above it.
@pytest.mark.timeout(180)
def test_companion_app_no_agent_exit0():
    """`--no-agent` on the companion app exits 0 and logs entropy redactions.

    This is the entropy-redaction canary. The companion app is a repo that
    previously made `repo-audit scan` exit 2: its benign `sha512-` integrity
    hashes tripped the entropy backstop, which used to hard-fail. The secret-lint
    is now split so the entropy backstop redacts-and-continues (value-blind),
    leaving gitleaks/known-patterns as the only hard blockers. So now:
      1. exit 0 (was exit 2).
      2. md + json reports are written under docs/state-reports/.
      3. meta.entropy_redactions is a NON-EMPTY list — proving the redact path
         actually RAN on the companion app's benign hashes, not that the buffer
         merely failed to trip.
    If a given machine's companion app somehow contains zero high-entropy
    tokens, item 3 would need downgrading to "field exists as a list" — but that
    is not the expected state of this canary repo.
    """
    companion = _skip_if_no_companion_app()
    result = subprocess.run(
        ["uv", "run", "repo-audit", "scan", "--no-agent", str(companion)],
        capture_output=True, timeout=120,
    )
    # 1. exit 0 (was exit 2 before the redact-and-continue split).
    assert result.returncode == 0, (
        f"repo-audit scan --no-agent on the companion app failed: "
        f"stderr={result.stderr.decode()[-2000:]}"
    )

    # 2. md + json reports for today exist.
    today = date.today().isoformat()
    md_path, json_path = _written_report_paths(result.stdout)
    assert today in md_path.name, f"report is not today's: {md_path}"
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
        "redact the companion app's benign high-entropy hashes — the "
        "redact-and-continue path did not run (or the buffer never tripped)."
    )
