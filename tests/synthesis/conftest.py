"""Shared fixtures + factories for the synthesis/prioritization suite.

Mirrors the `_mk` finding factory from `tests/test_agent_tools_summarize.py`
and seeds the extra fields the synthesis layer reads:
  - `evidence_type` + `dimension` + `file` feed the exploitability/blast-radius
    factor tables,
  - a fake `VerificationRecord` carries the tri-state `reachable` signal and the
    `candidate_token` dispatch identity (the 17-04 landmine — the score sidecar
    pairs finding↔record by token, never by the non-unique `build_finding_ref`),
  - a CVE-bearing SCA finding whose `evidence.parsed_value` has the literal
    `"cve"` key (the shape osv-scanner/grype emit) drives the KEV/EPSS fusion.

The KEV/EPSS loaders read the recorded fixtures under `fixtures/` so unit tests
never touch the network (the live EPSS fetch is the opt-in `-m integration` path).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from repo_audit.schema.finding import Evidence, Finding
from repo_audit.verification.record import VerificationRecord

_FIXTURES = Path(__file__).parent / "fixtures"


# -- finding factory -----------------------------------------------------

def make_finding(
    *,
    severity: str = "info",
    rule_id: str = "rule_a",
    file: str | None = "src/x.ts",
    line: int | None = 1,
    snippet: str = "snip",
    dimension: str = "quality",
    evidence_type: str = "heuristic",
    confidence: str = "high",
    parsed_value: dict[str, Any] | None = None,
    source_tool: str = "x",
) -> Finding:
    """Build a valid Finding seeding the synthesis-relevant fields.

    `evidence_type='heuristic'` + `confidence='high'` keep all five severities
    constructible (no critical+static caveat requirement, no candidate rung-cap),
    matching the `_mk` discipline in `tests/test_agent_tools_summarize.py`.
    """
    return Finding(
        dimension=dimension,
        severity=severity,
        file=file,
        line=line,
        evidence=Evidence(
            tool=source_tool,
            output_snippet=snippet,
            parsed_value=parsed_value or {},
            line_range=None,
        ),
        evidence_type=evidence_type,
        confidence=confidence,
        rule_id=rule_id,
        source_tool=source_tool,
    )


def make_record(
    *,
    candidate_token: int = -1,
    reachable: bool | None = None,
    final_confidence: str = "",
    finding_ref: str = "x::rule_a::src/x.ts:1",
) -> VerificationRecord:
    """Build a fake VerificationRecord carrying the tri-state reachability signal
    and the `candidate_token` dispatch identity the score sidecar pairs on."""
    return VerificationRecord(
        finding_ref=finding_ref,
        candidate_token=candidate_token,
        reachable=reachable,
        final_confidence=final_confidence,
    )


def make_cve_finding(
    *,
    cve: str,
    severity: str = "major",
    file: str | None = "package-lock.json",
    line: int | None = None,
    dimension: str = "security",
    confidence: str = "corroborated",
) -> Finding:
    """A CVE-bearing SCA finding whose `parsed_value` carries the literal `"cve"`
    key — the osv-scanner/grype shape (test_scan_runner_supply_chain L45)."""
    return Finding(
        dimension=dimension,
        severity=severity,
        file=file,
        line=line,
        evidence=Evidence(
            tool="osv-scanner",
            output_snippet=f"{cve} in left-pad@1.0.0",
            parsed_value={"cve": cve, "package": "left-pad", "version": "1.0.0"},
            line_range=None,
        ),
        evidence_type="static",
        confidence=confidence,
        rule_id=cve,
        source_tool="osv-scanner",
    )


# -- pytest fixtures -----------------------------------------------------

@pytest.fixture
def finding_factory():
    return make_finding


@pytest.fixture
def record_factory():
    return make_record


@pytest.fixture
def cve_finding_factory():
    return make_cve_finding


@pytest.fixture
def kev_set() -> set[str]:
    """The CVE ids in the recorded CISA KEV fixture, normalized upper-case."""
    raw = json.loads((_FIXTURES / "known_exploited_vulnerabilities.json").read_text())
    return {v["cveID"].strip().upper() for v in raw["vulnerabilities"]}


@pytest.fixture
def epss_map() -> dict[str, float]:
    """The CVE→epss float map from the recorded FIRST.org EPSS fixture."""
    raw = json.loads((_FIXTURES / "epss_response.json").read_text())
    return {row["cve"].strip().upper(): float(row["epss"]) for row in raw["data"]}
