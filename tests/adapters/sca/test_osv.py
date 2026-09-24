"""collect_osv unit tests (SCA-01 / SCA-03) against the recorded fixtures.

These tests never invoke a live binary: ``resolve_tool`` and ``run_tool`` are
monkeypatched so the recorded osv SARIF (Phase-6 fixture) and osv native JSON
(Plan 07-02 fixture) drive the parse + enrichment path. The contract proven:

    * findings come ONLY from the SARIF via the single ``sarif_to_findings``
      path (count == number of SARIF results);
    * scanner_version is lifted from the SARIF driver;
    * native JSON adds attributes (direct/transitive + fix) but NEVER a finding;
    * a resolve miss / parse failure degrades to ``status='unavailable'`` without
      raising (osv is the floor, D-07-10).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_audit.adapters import sca as sca_pkg
from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.sca import osv as osv_mod
from repo_audit.adapters.sca.osv import OsvResult, collect_osv

# Phase-6 recorded osv SARIF (the authoritative finding-source shape).
_SARIF_FIXTURE = (
    Path(__file__).parent.parent
    / "sarif"
    / "fixtures"
    / "osv-scanner"
    / "sample.sarif"
)
# Plan 07-02 recorded osv native JSON (the enrichment source).
_JSON_FIXTURE = Path(__file__).parent / "fixtures" / "osv-scanner" / "sample.json"


@pytest.fixture
def osv_sarif_text() -> str:
    return _SARIF_FIXTURE.read_text(encoding="utf-8")


@pytest.fixture
def osv_json_text() -> str:
    return _JSON_FIXTURE.read_text(encoding="utf-8")


def _patch_osv(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sarif_stdout: str,
    json_stdout: str,
    sarif_returncode: int = 1,  # osv exits 1 when it FINDS vulns (not a failure)
    json_returncode: int = 1,
    sarif_stderr: str = "",
    resolve_to: Path | None = Path("/vendor/osv-scanner/osv-scanner"),
) -> None:
    """Monkeypatch resolve_tool + run_tool in the osv module.

    run_tool returns the SARIF stdout on the first call (--format sarif) and the
    JSON stdout on the second (--format json), keyed on the argv contents.
    """
    monkeypatch.setattr(osv_mod, "resolve_tool", lambda tool, repo, **_kw: resolve_to)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        is_sarif = "sarif" in argv
        return InvocationResult(
            stdout=sarif_stdout if is_sarif else json_stdout,
            stderr=sarif_stderr if is_sarif else "",
            returncode=sarif_returncode if is_sarif else json_returncode,
            command=list(argv),
        )

    monkeypatch.setattr(osv_mod, "run_tool", fake_run_tool)


def test_collect_osv_emits_one_finding_per_sarif_result(
    monkeypatch, osv_sarif_text, osv_json_text
):
    """SCA-01: findings count == number of SARIF results (single source)."""
    _patch_osv(
        monkeypatch, sarif_stdout=osv_sarif_text, json_stdout=osv_json_text
    )
    sarif = json.loads(osv_sarif_text)
    expected = sum(len(run.get("results") or []) for run in sarif["runs"])

    result = collect_osv(Path("/repo"), env={})

    assert result.status == "ok"
    assert len(result.findings) == expected == 1


def test_collect_osv_findings_are_security_candidate(
    monkeypatch, osv_sarif_text, osv_json_text
):
    """Every osv finding routes to the security dimension at candidate."""
    _patch_osv(
        monkeypatch, sarif_stdout=osv_sarif_text, json_stdout=osv_json_text
    )
    result = collect_osv(Path("/repo"), env={})
    f = result.findings[0]
    assert f.dimension == "security"
    assert f.confidence == "candidate"
    assert f.source_tool == "osv-scanner"
    assert f.evidence_type == "static"


def test_collect_osv_extracts_scanner_version(
    monkeypatch, osv_sarif_text, osv_json_text
):
    """scanner_version is lifted from the SARIF driver (FeedProvenance, Plan 05)."""
    _patch_osv(
        monkeypatch, sarif_stdout=osv_sarif_text, json_stdout=osv_json_text
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.scanner_version == "2.3.8"


def test_collect_osv_enriches_with_fix_version(
    monkeypatch, osv_sarif_text, osv_json_text
):
    """SCA-03: the urllib3/CVE-2025-66471 finding is enriched fixed=2.6.0."""
    _patch_osv(
        monkeypatch, sarif_stdout=osv_sarif_text, json_stdout=osv_json_text
    )
    result = collect_osv(Path("/repo"), env={})
    f = result.findings[0]
    assert f.rule_id == "CVE-2025-66471"
    assert f.evidence.parsed_value["fixed_version"] == "2.6.0"
    # dependency_groups is null for a flat requirements.txt -> direct UNKNOWN (A4).
    assert f.evidence.parsed_value["direct"] is None
    assert f.recommendation == "upgrade to 2.6.0"


def test_enrichment_does_not_inflate_count(
    monkeypatch, osv_sarif_text, osv_json_text
):
    """JSON adds attributes only; finding count == SARIF result count."""
    _patch_osv(
        monkeypatch, sarif_stdout=osv_sarif_text, json_stdout=osv_json_text
    )
    sarif = json.loads(osv_sarif_text)
    sarif_result_count = sum(
        len(run.get("results") or []) for run in sarif["runs"]
    )
    result = collect_osv(Path("/repo"), env={})
    assert len(result.findings) == sarif_result_count


def test_collect_osv_unavailable_on_resolve_miss(monkeypatch):
    """osv not found -> status='unavailable', no raise (floor, D-07-10)."""
    _patch_osv(
        monkeypatch, sarif_stdout="", json_stdout="", resolve_to=None
    )
    result = collect_osv(Path("/repo"), env={})
    assert isinstance(result, OsvResult)
    assert result.status == "unavailable"
    assert result.findings == []
    assert "not found" in result.notes


def test_collect_osv_unavailable_on_unparseable_sarif(monkeypatch, osv_json_text):
    """A non-JSON SARIF stdout -> unavailable, never raises."""
    _patch_osv(
        monkeypatch,
        sarif_stdout="not json at all <<<",
        json_stdout=osv_json_text,
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.status == "unavailable"
    assert result.findings == []


def test_collect_osv_timeout(monkeypatch, osv_json_text):
    """A -2 timeout sentinel on the SARIF run -> status='timeout'."""
    _patch_osv(
        monkeypatch,
        sarif_stdout="",
        json_stdout=osv_json_text,
        sarif_returncode=-2,
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.status == "timeout"
    assert result.findings == []


def test_collect_osv_bad_json_enrichment_is_non_fatal(
    monkeypatch, osv_sarif_text
):
    """A broken native-JSON does NOT drop the SARIF findings (enrichment best-effort)."""
    _patch_osv(
        monkeypatch,
        sarif_stdout=osv_sarif_text,
        json_stdout="<<< not json >>>",
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.status == "ok"
    assert len(result.findings) == 1
    # Enrichment unavailable -> direct/fixed default to UNKNOWN (None), not a crash.
    assert result.findings[0].evidence.parsed_value["fixed_version"] is None


# ---- Exit-code contract: 0 clean, 1 vulns found, anything else is an error. ----

_EMPTY_SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "osv-scanner", "version": "2.3.8"}},
                  "results": []}],
    }
)


def test_collect_osv_no_local_db_is_unavailable_not_clean(monkeypatch, osv_json_text):
    """Exit 127 with a valid empty SARIF is a dead DB, never a clean scan."""
    _patch_osv(
        monkeypatch,
        sarif_stdout=_EMPTY_SARIF,
        json_stdout=osv_json_text,
        sarif_returncode=127,
        sarif_stderr="no offline version of the OSV database is available",
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.status == "unavailable"
    assert result.findings == []
    assert "127" in result.notes
    assert "no offline version of the OSV database" in result.notes


def test_collect_osv_no_packages_is_unavailable(monkeypatch, osv_json_text):
    """Exit 128 (no packages found) is reported unavailable."""
    _patch_osv(
        monkeypatch,
        sarif_stdout=_EMPTY_SARIF,
        json_stdout=osv_json_text,
        sarif_returncode=128,
        sarif_stderr="No package sources found",
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.status == "unavailable"
    assert result.findings == []
    assert "128" in result.notes


def test_collect_osv_could_not_load_db_is_unavailable(monkeypatch, osv_json_text):
    """Exit 0 but 'could not load db' on stderr (any case) is unavailable."""
    _patch_osv(
        monkeypatch,
        sarif_stdout=_EMPTY_SARIF,
        json_stdout=osv_json_text,
        sarif_returncode=0,
        sarif_stderr="Warning: Could Not Load DB for ecosystem npm",
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.status == "unavailable"
    assert result.findings == []


def test_collect_osv_clean_exit_zero_is_ok(monkeypatch, osv_json_text):
    """Exit 0 with an empty SARIF and quiet stderr is a genuine clean scan."""
    _patch_osv(
        monkeypatch,
        sarif_stdout=_EMPTY_SARIF,
        json_stdout=osv_json_text,
        sarif_returncode=0,
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.status == "ok"
    assert result.findings == []


def test_collect_osv_stderr_tail_is_bounded_and_single_line(monkeypatch, osv_json_text):
    _patch_osv(
        monkeypatch,
        sarif_stdout=_EMPTY_SARIF,
        json_stdout=osv_json_text,
        sarif_returncode=127,
        sarif_stderr=("line one\n" * 2000) + "no offline version of the OSV database",
    )
    result = collect_osv(Path("/repo"), env={})
    assert result.status == "unavailable"
    assert "\n" not in result.notes
    assert len(result.notes) < 1000


def test_adapter_config_loaded_safe_and_osv_security():
    """adapter.yaml loads (safe mode) and routes osv-scanner -> security."""
    cfg = sca_pkg.ADAPTER_CONFIG
    assert cfg is sca_pkg.CONFIG
    assert cfg["tools"]["osv-scanner"]["default_dimension"] == "security"
    assert cfg["tools"]["osv-scanner"]["severity_map"] == {}
