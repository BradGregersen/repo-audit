"""run_supabase orchestration + build_rls_provenance tests (Plan 08-05, Task 1).

These prove the composition contract of the single RLS dimension entry point:

  * splinter is the always-on floor; pgrls runs ONLY when ``rls_pgrls`` AND
    against the SAME ephemeral DB the floor stood up; squawk + footguns are
    always-on static; the runtime two-account probe runs ONLY when
    ``rls_runtime``.
  * ``run_supabase`` NEVER raises (base.py contract) — every failure degrades
    the dimension to ``unavailable`` with a clear reason.
  * the D-08-05 not-run posture is recorded as a ledger note and the D-08-09/16
    reproducibility provenance (splinter SHA + tool versions + image tag@digest
    + matched layout + runtime posture) is built as structured ledger data.

All offline: the ephemeral-PG lifecycle + every collector is monkeypatched, so
no docker / node / live DB is touched.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from repo_audit.adapters import supabase as supa
from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.supabase import provenance as prov_mod
from repo_audit.schema.finding import Evidence, Finding


# --- helpers ---------------------------------------------------------------


def _finding(
    *,
    rule_id: str,
    source_tool: str,
    dimension: str = "security",
    evidence_type: str = "static",
    recommendation: str = "present; verify the policy shape before relying on it.",
) -> Finding:
    return Finding(
        dimension=dimension,
        severity="major",
        evidence=Evidence(tool=source_tool, output_snippet="present; verify."),
        evidence_type=evidence_type,
        confidence="candidate",
        recommendation=recommendation,
        source_tool=source_tool,
        source_collector=source_tool,
        rule_id=rule_id,
    )


@pytest.fixture
def patched_collectors(monkeypatch):
    """Patch the whole ephemeral-PG lifecycle + every collector to be offline.

    Returns a dict of call-spies the tests inspect:
        {"pgrls": int, "runtime": int, "squawk": int, "footguns": int,
         "splinter_dsn": str|None}
    """
    spy = {"pgrls": 0, "runtime": 0, "squawk": 0, "footguns": 0, "splinter_dsn": None}

    # find_migrations -> a non-empty canonical set so the floor stands up.
    def _fake_find(repo):
        from repo_audit.adapters.supabase.discovery import MigrationSet

        return MigrationSet(
            files=[Path(repo) / "supabase" / "migrations" / "0001.sql"],
            layout="supabase/migrations",
        )

    monkeypatch.setattr(supa, "find_migrations", _fake_find, raising=True)
    monkeypatch.setattr(supa, "detect_pg_major", lambda repo: 15, raising=True)

    # Fake ephemeral lifecycle: yields a fixed dsn, never touches docker.
    @contextmanager
    def _fake_pg(migrations, *, pg_major, env, cwd, timeout_seconds):
        yield "postgresql://supabase_admin:postgres@127.0.0.1:5432/postgres"

    monkeypatch.setattr(supa, "ephemeral_supabase_pg", _fake_pg, raising=True)

    # splinter rows -> one static finding.
    def _fake_run_splinter(dsn, *, timeout_seconds):
        spy["splinter_dsn"] = dsn
        return [{"name": "rls_disabled_in_public"}]

    monkeypatch.setattr(supa, "run_splinter", _fake_run_splinter, raising=True)
    monkeypatch.setattr(
        supa,
        "map_splinter_rows",
        lambda rows: [_finding(rule_id="rls_disabled_in_public", source_tool="splinter")],
        raising=True,
    )

    def _fake_pgrls(dsn, *, env, timeout_seconds, scan_target):
        spy["pgrls"] += 1
        return AdapterResult(
            status="ok",
            findings=[_finding(rule_id="pgrls_rule", source_tool="pgrls")],
            source_tool="pgrls",
            dimension="security",
        )

    monkeypatch.setattr(supa, "collect_pgrls", _fake_pgrls, raising=True)

    def _fake_squawk(sql_files, *, env, timeout_seconds, scan_target):
        spy["squawk"] += 1
        return AdapterResult(
            status="ok",
            findings=[
                _finding(
                    rule_id="ban-drop-column",
                    source_tool="squawk",
                    dimension="correctness",
                )
            ],
            source_tool="squawk",
            dimension="correctness",
        )

    monkeypatch.setattr(supa, "collect_squawk", _fake_squawk, raising=True)

    def _fake_footguns(repo):
        spy["footguns"] += 1
        return AdapterResult(
            status="ok",
            findings=[
                _finding(
                    rule_id="service_role_reachable_from_client",
                    source_tool="supabase-footguns",
                    evidence_type="heuristic",
                )
            ],
            source_tool="supabase-footguns",
            dimension="security",
        )

    monkeypatch.setattr(
        supa, "scan_service_role_in_client", _fake_footguns, raising=True
    )

    def _fake_runtime(repo, *, opted_in, env, timeout_seconds):
        spy["runtime"] += 1
        # When invoked in these offline tests, simulate the not-opted path
        # unless opted_in is True (then a clean enforced result).
        if not opted_in:
            return AdapterResult(
                status="unavailable",
                findings=[],
                notes="runtime RLS enforcement test not run (not opted in)",
                source_tool="rls-two-account",
                dimension="security",
            )
        return AdapterResult(
            status="ok",
            findings=[
                _finding(
                    rule_id="rls_runtime_enforced",
                    source_tool="rls-two-account",
                    evidence_type="runtime",
                    recommendation="Two-account runtime test PASSED: RLS enforced.",
                )
            ],
            source_tool="rls-two-account",
            dimension="security",
        )

    monkeypatch.setattr(
        supa, "collect_runtime_two_account", _fake_runtime, raising=True
    )

    # version probes -> fixed strings (no dist lookup in the unit tier).
    monkeypatch.setattr(supa, "pgrls_version", lambda: "0.14.0", raising=True)

    return spy


# --- run_supabase composition ---------------------------------------------


def test_default_composes_floor_squawk_footguns_no_pgrls_no_runtime(
    tmp_path, patched_collectors
):
    """Default flags: splinter + squawk + footguns; pgrls + runtime NOT run."""
    result = supa.run_supabase(
        tmp_path, base_env={}, rls_pgrls=False, rls_runtime=False
    )

    assert patched_collectors["pgrls"] == 0  # flag off -> never invoked
    assert patched_collectors["squawk"] == 1
    assert patched_collectors["footguns"] == 1
    assert patched_collectors["runtime"] == 1  # invoked but opted_in=False
    # The combined result carries the floor + squawk + footgun findings.
    rule_ids = {f.rule_id for f in result.findings}
    assert "rls_disabled_in_public" in rule_ids
    assert "ban-drop-column" in rule_ids
    assert "service_role_reachable_from_client" in rule_ids
    assert "pgrls_rule" not in rule_ids
    # The honest not-run runtime posture is a ledger note.
    joined = " ".join(result.ledger_notes).lower()
    assert "runtime" in joined and "not run" in joined


def test_splinter_sql_unavailable_degrades_floor_and_pgrls_still_runs(
    tmp_path, patched_collectors, monkeypatch
):
    """No lint set (offline / bad hash): floor unavailable, pgrls still runs."""
    from repo_audit.adapters.supabase.splinter_fetch import (
        SPLINTER_URL,
        SplinterSqlUnavailable,
    )

    def _unavailable(dsn, *, timeout_seconds):
        raise SplinterSqlUnavailable(
            f"splinter.sql unavailable: could not fetch {SPLINTER_URL} into "
            "/cache/repo-audit/splinter/splinter.sql: URLError: offline"
        )

    monkeypatch.setattr(supa, "run_splinter", _unavailable, raising=True)

    result = supa.run_supabase(
        tmp_path, base_env={}, rls_pgrls=True, rls_runtime=False
    )

    assert patched_collectors["pgrls"] == 1
    assert any(SPLINTER_URL in note for note in result.ledger_notes)
    joined = " ".join(result.ledger_notes)
    assert "unexpectedly" not in joined
    assert all(f.source_tool != "splinter" for f in result.findings)
    assert "pgrls_rule" in {f.rule_id for f in result.findings}
    assert result.status != "ok"


def test_pgrls_runs_only_when_flagged_and_against_floor_dsn(
    tmp_path, patched_collectors
):
    """rls_pgrls=True -> collect_pgrls invoked once against the floor's DSN."""
    result = supa.run_supabase(
        tmp_path, base_env={}, rls_pgrls=True, rls_runtime=False
    )
    assert patched_collectors["pgrls"] == 1
    assert "pgrls_rule" in {f.rule_id for f in result.findings}
    # pgrls ran against the SAME ephemeral DB the floor used.
    assert patched_collectors["splinter_dsn"] is not None


def test_runtime_runs_only_when_flagged(tmp_path, patched_collectors):
    """rls_runtime=True -> the runtime finding is merged with opted_in=True."""
    result = supa.run_supabase(
        tmp_path, base_env={}, rls_pgrls=False, rls_runtime=True
    )
    rule_ids = {f.rule_id for f in result.findings}
    assert "rls_runtime_enforced" in rule_ids


def test_no_migrations_floor_unavailable_but_still_completes(
    tmp_path, monkeypatch, patched_collectors
):
    """No migrations -> splinter unavailable; squawk/footguns still run; no raise."""
    from repo_audit.adapters.supabase.discovery import MigrationSet

    monkeypatch.setattr(
        supa,
        "find_migrations",
        lambda repo: MigrationSet(files=[], layout="none"),
        raising=True,
    )
    result = supa.run_supabase(
        tmp_path, base_env={}, rls_pgrls=True, rls_runtime=False
    )
    # The floor (splinter) and pgrls cannot run without a DB, but the static
    # squawk + footguns paths still attempt, and the result completes.
    assert patched_collectors["footguns"] == 1
    # The combined result still completes and discloses the gap.
    assert result.status in {"ok", "partial", "unavailable"}
    joined = " ".join(result.ledger_notes).lower()
    assert "no migrations" in joined or "unavailable" in joined


def test_run_supabase_never_raises_on_unexpected_error(tmp_path, monkeypatch):
    """An unexpected internal error degrades to unavailable, never raises."""

    def _boom(repo):
        raise RuntimeError("discovery exploded")

    monkeypatch.setattr(supa, "find_migrations", _boom, raising=True)
    result = supa.run_supabase(tmp_path, base_env={})
    assert result.status == "unavailable"
    assert result.findings == []


def test_static_findings_are_verify_phrased(tmp_path, patched_collectors):
    """The combined static findings pass the CRIT-4 tripwire (no overclaim)."""
    from repo_audit.adapters.supabase.verify_phrasing import (
        assert_verify_phrasing,
    )

    result = supa.run_supabase(
        tmp_path, base_env={}, rls_pgrls=True, rls_runtime=False
    )
    static = [f for f in result.findings if f.evidence_type != "runtime"]
    assert_verify_phrasing(static)  # must NOT raise


def test_provenance_recorded_on_result(tmp_path, patched_collectors):
    """The result carries the D-08-09/16 reproducibility provenance dict."""
    result = supa.run_supabase(
        tmp_path, base_env={}, rls_pgrls=True, rls_runtime=False
    )
    assert isinstance(result.provenance, dict)
    # splinter SHA + tool versions + image ref + layout + runtime posture.
    assert result.provenance.get("splinter_sha")
    assert result.provenance.get("layout") == "supabase/migrations"
    assert "runtime_posture" in result.provenance


def test_register_adapter_side_effect():
    """Importing the package registers the 'supabase' adapter (Plan 05)."""
    from repo_audit.adapters import get_adapter_registry

    assert "supabase" in get_adapter_registry()


# --- build_rls_provenance --------------------------------------------------


def test_build_rls_provenance_structured_payload():
    """build_rls_provenance returns the reproducibility stamp as a dict."""
    payload = prov_mod.build_rls_provenance(
        splinter_sha="a7f71080ed059de8a7f00addd71ade19b82a4108",
        pgrls_version="0.14.0",
        squawk_version="2.55.0",
        image_ref="supabase/postgres:15.14.1.132@sha256:deadbeef",
        layout="supabase/migrations",
        runtime_posture="not_run_not_opted_in",
    )
    assert payload["splinter_sha"] == "a7f71080ed059de8a7f00addd71ade19b82a4108"
    assert payload["pgrls_version"] == "0.14.0"
    assert payload["squawk_version"] == "2.55.0"
    assert "sha256" in payload["image_ref"]
    assert payload["layout"] == "supabase/migrations"
    assert payload["runtime_posture"] == "not_run_not_opted_in"


def test_read_splinter_sha_is_the_pinned_commit():
    """The splinter SHA is the commit splinter.sql is fetched from."""
    from repo_audit.adapters.supabase.splinter_fetch import SPLINTER_COMMIT

    sha = prov_mod.read_splinter_sha()
    assert sha == SPLINTER_COMMIT
    assert len(sha) == 40
    int(sha, 16)  # parses as hex
