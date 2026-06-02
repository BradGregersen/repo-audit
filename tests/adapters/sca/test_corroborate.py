"""grype collection + corroboration union tests (SCA-02 / D-07-06).

Never invokes a live binary: ``resolve_tool`` / ``run_tool`` are monkeypatched so
the recorded grype SARIF + grype JSON (Plan 07-02 fixtures) drive ``collect_grype``,
and the osv SARIF + osv JSON drive ``collect_osv``. The contracts proven:

    * grype routes through the SINGLE ``sarif_to_findings`` path (source_tool="grype");
    * grype's COMPOSITE ruleId is correctly re-keyed so its ``(cve,pkg,version)``
      key EQUALS osv's for the shared urllib3 CVE (Pitfall 2);
    * the corroboration union yields ONE finding per distinct key (no inflation),
      bumps both-agree findings candidate -> corroborated, keeps single-source
      (incl. grype-only) at candidate but STILL present (D-07-10);
    * count invariant: union length == number of distinct keys.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_audit.adapters.base import InvocationResult
from repo_audit.adapters.sca import grype as grype_mod
from repo_audit.adapters.sca import osv as osv_mod
from repo_audit.adapters.sca.corroborate import corroborate
from repo_audit.adapters.sca.enrich import enrichment_key_for
from repo_audit.adapters.sca.grype import GrypeResult, collect_grype
from repo_audit.adapters.sca.osv import collect_osv

# Recorded fixtures (frozen Plan 07-02 / Phase 6).
_GRYPE_SARIF = Path(__file__).parent / "fixtures" / "grype" / "sample.sarif"
_GRYPE_JSON = Path(__file__).parent / "fixtures" / "grype" / "sample.json"
_OSV_SARIF = (
    Path(__file__).parent.parent / "sarif" / "fixtures" / "osv-scanner" / "sample.sarif"
)
_OSV_JSON = Path(__file__).parent / "fixtures" / "osv-scanner" / "sample.json"


@pytest.fixture
def grype_sarif_text() -> str:
    return _GRYPE_SARIF.read_text(encoding="utf-8")


@pytest.fixture
def grype_json_text() -> str:
    return _GRYPE_JSON.read_text(encoding="utf-8")


@pytest.fixture
def osv_sarif_text() -> str:
    return _OSV_SARIF.read_text(encoding="utf-8")


@pytest.fixture
def osv_json_text() -> str:
    return _OSV_JSON.read_text(encoding="utf-8")


def _patch_grype(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sarif_stdout: str,
    json_stdout: str,
    sarif_returncode: int = 1,  # grype exits non-zero when it FINDS vulns
    json_returncode: int = 1,
    resolve_to: Path | None = Path("/vendor/grype/grype"),
) -> None:
    monkeypatch.setattr(grype_mod, "resolve_tool", lambda tool, repo: resolve_to)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        is_sarif = "sarif" in argv
        return InvocationResult(
            stdout=sarif_stdout if is_sarif else json_stdout,
            stderr="",
            returncode=sarif_returncode if is_sarif else json_returncode,
            command=list(argv),
        )

    monkeypatch.setattr(grype_mod, "run_tool", fake_run_tool)


def _patch_osv(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sarif_stdout: str,
    json_stdout: str,
    resolve_to: Path | None = Path("/vendor/osv-scanner/osv-scanner"),
) -> None:
    monkeypatch.setattr(osv_mod, "resolve_tool", lambda tool, repo: resolve_to)

    def fake_run_tool(argv, *, env, cwd, timeout_seconds):
        is_sarif = "sarif" in argv
        return InvocationResult(
            stdout=sarif_stdout if is_sarif else json_stdout,
            stderr="",
            returncode=1,
            command=list(argv),
        )

    monkeypatch.setattr(osv_mod, "run_tool", fake_run_tool)


# --------------------------------------------------------------------------- #
# Task 1 — collect_grype
# --------------------------------------------------------------------------- #


def test_grype_emits_one_finding_per_sarif_result(
    monkeypatch, grype_sarif_text, grype_json_text
):
    """grype findings come ONLY from the SARIF (count == SARIF results)."""
    _patch_grype(monkeypatch, sarif_stdout=grype_sarif_text, json_stdout=grype_json_text)
    sarif = json.loads(grype_sarif_text)
    expected = sum(len(run.get("results") or []) for run in sarif["runs"])

    result = collect_grype(Path("/repo"), env={})

    assert result.status == "ok"
    assert len(result.findings) == expected == 11


def test_grype_findings_are_security_candidate(
    monkeypatch, grype_sarif_text, grype_json_text
):
    """Every grype finding routes to security at candidate, source_tool=grype."""
    _patch_grype(monkeypatch, sarif_stdout=grype_sarif_text, json_stdout=grype_json_text)
    result = collect_grype(Path("/repo"), env={})
    for f in result.findings:
        assert f.dimension == "security"
        assert f.confidence == "candidate"
        assert f.source_tool == "grype"
        assert f.evidence_type == "static"


def test_grype_key_equals_osv_key_for_shared_cve(
    monkeypatch,
    grype_sarif_text,
    grype_json_text,
    osv_sarif_text,
    osv_json_text,
):
    """Pitfall 2: grype's composite ruleId is re-keyed so its (cve,pkg,version)
    key EQUALS osv's for the shared urllib3 CVE-2025-66471."""
    _patch_grype(monkeypatch, sarif_stdout=grype_sarif_text, json_stdout=grype_json_text)
    grype_result = collect_grype(Path("/repo"), env={})

    _patch_osv(monkeypatch, sarif_stdout=osv_sarif_text, json_stdout=osv_json_text)
    osv_result = collect_osv(Path("/repo"), env={})

    osv_finding = osv_result.findings[0]
    osv_key = enrichment_key_for(osv_finding)
    assert osv_key == ("CVE-2025-66471", "urllib3", "1.23.0")

    grype_keys = {enrichment_key_for(f) for f in grype_result.findings}
    # The grype finding for the same advisory must produce the IDENTICAL key
    # (composite ruleId GHSA-2xpw-w6gg-jr37-urllib3 -> CVE-2025-66471).
    assert osv_key in grype_keys


def test_grype_restamps_bare_cve_not_composite_rule_id(
    monkeypatch, grype_sarif_text, grype_json_text
):
    """The re-extracted CVE lives in parsed_value; rule_id stays the composite."""
    _patch_grype(monkeypatch, sarif_stdout=grype_sarif_text, json_stdout=grype_json_text)
    result = collect_grype(Path("/repo"), env={})
    keyed = {f.evidence.parsed_value.get("cve") for f in result.findings}
    assert "CVE-2025-66471" in keyed
    # rule_id is NOT mutated to the bare CVE — it stays the SARIF composite.
    assert all(f.rule_id.startswith("GHSA-") for f in result.findings)


def test_grype_extracts_db_snapshot_date(
    monkeypatch, grype_sarif_text, grype_json_text
):
    """db_snapshot_date is lifted from descriptor.db.status.built (FeedProvenance)."""
    _patch_grype(monkeypatch, sarif_stdout=grype_sarif_text, json_stdout=grype_json_text)
    result = collect_grype(Path("/repo"), env={})
    assert result.db_snapshot_date == "2026-06-01T08:11:23Z"
    assert result.scanner_version == "0.112.0"


def test_grype_unavailable_on_resolve_miss(monkeypatch):
    """grype not found -> unavailable, no raise (OPTIONAL, osv-only continues)."""
    _patch_grype(monkeypatch, sarif_stdout="", json_stdout="", resolve_to=None)
    result = collect_grype(Path("/repo"), env={})
    assert isinstance(result, GrypeResult)
    assert result.status == "unavailable"
    assert result.findings == []


def test_grype_unavailable_on_unparseable_sarif(monkeypatch, grype_json_text):
    """A non-JSON SARIF stdout -> unavailable, never raises."""
    _patch_grype(
        monkeypatch, sarif_stdout="not json <<<", json_stdout=grype_json_text
    )
    result = collect_grype(Path("/repo"), env={})
    assert result.status == "unavailable"


def test_grype_timeout(monkeypatch, grype_json_text):
    """A -2 timeout sentinel on the SARIF run -> status='timeout'."""
    _patch_grype(
        monkeypatch,
        sarif_stdout="",
        json_stdout=grype_json_text,
        sarif_returncode=-2,
    )
    result = collect_grype(Path("/repo"), env={})
    assert result.status == "timeout"


# --------------------------------------------------------------------------- #
# Task 2 — corroborate union
# --------------------------------------------------------------------------- #


def _osv_findings(monkeypatch, osv_sarif_text, osv_json_text):
    _patch_osv(monkeypatch, sarif_stdout=osv_sarif_text, json_stdout=osv_json_text)
    return collect_osv(Path("/repo"), env={}).findings


def _grype_findings(monkeypatch, grype_sarif_text, grype_json_text):
    _patch_grype(monkeypatch, sarif_stdout=grype_sarif_text, json_stdout=grype_json_text)
    return collect_grype(Path("/repo"), env={}).findings


def test_corroborated_when_both_tools_agree(
    monkeypatch, osv_sarif_text, osv_json_text, grype_sarif_text, grype_json_text
):
    """Same (cve,pkg,version) in osv + grype -> ONE finding at corroborated."""
    osv_f = _osv_findings(monkeypatch, osv_sarif_text, osv_json_text)
    grype_f = _grype_findings(monkeypatch, grype_sarif_text, grype_json_text)

    out = corroborate(osv_f, grype_f)
    shared = [f for f in out if enrichment_key_for(f)[0] == "CVE-2025-66471"]
    assert len(shared) == 1
    assert shared[0].confidence == "corroborated"
    assert shared[0].confidence_caveat
    assert "grype" in shared[0].confidence_caveat.lower()


def test_count_invariant_union_equals_distinct_keys(
    monkeypatch, osv_sarif_text, osv_json_text, grype_sarif_text, grype_json_text
):
    """SCA-02 no inflation: output count == number of distinct (cve,pkg,version)."""
    osv_f = _osv_findings(monkeypatch, osv_sarif_text, osv_json_text)
    grype_f = _grype_findings(monkeypatch, grype_sarif_text, grype_json_text)

    distinct_keys = {enrichment_key_for(f) for f in (*osv_f, *grype_f)}
    out = corroborate(osv_f, grype_f)
    assert len(out) == len(distinct_keys)


def test_osv_only_finding_stays_candidate(monkeypatch, osv_sarif_text, osv_json_text):
    """osv-only (no grype partner) stays candidate and is present."""
    osv_f = _osv_findings(monkeypatch, osv_sarif_text, osv_json_text)
    out = corroborate(osv_f, [])
    assert len(out) == len(osv_f)
    assert all(f.confidence == "candidate" for f in out)


def test_grype_only_finding_survives_at_candidate(
    monkeypatch, grype_sarif_text, grype_json_text
):
    """D-07-10: grype-only findings are NEVER dropped; they stay candidate."""
    grype_f = _grype_findings(monkeypatch, grype_sarif_text, grype_json_text)
    out = corroborate([], grype_f)
    distinct = {enrichment_key_for(f) for f in grype_f}
    assert len(out) == len(distinct)
    assert all(f.confidence == "candidate" for f in out)


def test_corroborated_severity_not_re_raised(
    monkeypatch, osv_sarif_text, osv_json_text, grype_sarif_text, grype_json_text
):
    """The bump changes confidence ONLY; severity stays capped (Phase 17 promotes)."""
    osv_f = _osv_findings(monkeypatch, osv_sarif_text, osv_json_text)
    grype_f = _grype_findings(monkeypatch, grype_sarif_text, grype_json_text)

    osv_shared = next(
        f for f in osv_f if enrichment_key_for(f)[0] == "CVE-2025-66471"
    )
    pre_cap_severity = osv_shared.severity

    out = corroborate(osv_f, grype_f)
    shared = next(f for f in out if enrichment_key_for(f)[0] == "CVE-2025-66471")
    assert shared.severity == pre_cap_severity  # unchanged by corroboration


def test_corroboration_prefers_osv_enrichment(
    monkeypatch, osv_sarif_text, osv_json_text, grype_sarif_text, grype_json_text
):
    """Merged finding keeps osv's enrichment (fixed_version) — osv is primary."""
    osv_f = _osv_findings(monkeypatch, osv_sarif_text, osv_json_text)
    grype_f = _grype_findings(monkeypatch, grype_sarif_text, grype_json_text)

    out = corroborate(osv_f, grype_f)
    shared = next(f for f in out if enrichment_key_for(f)[0] == "CVE-2025-66471")
    assert shared.source_tool == "osv-scanner"
    assert shared.evidence.parsed_value.get("fixed_version") == "2.6.0"


def test_corroborate_output_is_deterministically_sorted(
    monkeypatch, osv_sarif_text, osv_json_text, grype_sarif_text, grype_json_text
):
    """SC-5: re-runs produce a stable order (sorted by key)."""
    osv_f = _osv_findings(monkeypatch, osv_sarif_text, osv_json_text)
    grype_f = _grype_findings(monkeypatch, grype_sarif_text, grype_json_text)

    keys_a = [enrichment_key_for(f) for f in corroborate(osv_f, grype_f)]
    keys_b = [enrichment_key_for(f) for f in corroborate(osv_f, grype_f)]
    assert keys_a == keys_b == sorted(keys_a)
