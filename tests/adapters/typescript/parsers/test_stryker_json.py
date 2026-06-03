"""TST-02 (Stryker) — mutation-score computation contract (Plan 11-01 Wave 0).

SKIPPED until the Wave-1
``repo_audit.adapters.typescript.parsers.stryker_json`` module lands, then
activates automatically.

StrykerJS's ``mutation.json`` (mutation-testing-report-schema v1/v2) has NO
top-level ``mutationScore`` field (11-RESEARCH Pitfall 2) — the score is COMPUTED
from per-file mutant statuses:

    detected = count(status in {Killed, Timeout})
    valid    = count(status in {Killed, Survived, Timeout, NoCoverage})
    score    = round(100 * detected / valid, 1)     # Ignored excluded from BOTH

The recorded fixture has two files (one well-tested, one weakly tested) with
mutant statuses covering Killed/Survived/Timeout/NoCoverage/Ignored, so the
denominator rule + the per-file WEAK-test gap signal (D-11-06) are both
exercised. The expected score is computed in-test from the fixture so the test
does not bake a magic constant.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

stryker = pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.stryker_json",
    reason="Wave 1 (plan 11-04) not yet landed — parsers.stryker_json missing",
)

_FIXTURE = Path(__file__).parent / "fixtures" / "stryker-mutation.json"

_DETECTED = {"Killed", "Timeout"}
_VALID = {"Killed", "Survived", "Timeout", "NoCoverage"}


def _load() -> dict:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _expected_score(report: dict) -> float:
    """Hand-compute the Pitfall-2 score directly from the fixture mutant counts."""
    detected = valid = 0
    for fdata in report["files"].values():
        for mutant in fdata["mutants"]:
            status = mutant["status"]
            if status in _VALID:
                valid += 1
                if status in _DETECTED:
                    detected += 1
    return round(100.0 * detected / valid, 1) if valid else 0.0


def test_score_computed_from_mutant_statuses():
    """compute_mutation_score equals the hand-computed detected/valid ratio."""
    report = _load()
    expected = _expected_score(report)
    # Sanity-check the fixture itself encodes the intended 50.0 (4 detected / 8 valid).
    assert expected == 50.0

    assert stryker.compute_mutation_score(report) == expected


def test_score_excludes_ignored_from_denominator():
    """An extra Ignored mutant must NOT change the computed score (denominator rule)."""
    report = _load()
    base = stryker.compute_mutation_score(report)

    first_file = next(iter(report["files"]))
    report["files"][first_file]["mutants"].append(
        {"id": "extra", "mutatorName": "StringLiteral", "status": "Ignored"}
    )

    assert stryker.compute_mutation_score(report) == base


def test_per_file_kill_data_available():
    """per_file_scores exposes per-path detected/valid for the WEAK-test signal (D-11-06)."""
    report = _load()
    per_file = stryker.per_file_scores(report)

    # One entry per file in the fixture.
    assert set(per_file) == set(report["files"])
    # The weakly-tested file has a strictly lower detected/valid ratio than the
    # well-tested one (the WEAK gap signal must be derivable).
    well = per_file["src/wellTested.ts"]
    weak = per_file["src/weaklyTested.ts"]

    def _ratio(entry) -> float:
        valid = entry["valid"]
        return entry["detected"] / valid if valid else 0.0

    assert _ratio(weak) < _ratio(well)


def test_partial_report_on_timeout_yields_score():
    """A report with only one file present still computes (no KeyError) -> D-11-05 partial path."""
    report = _load()
    first_file = next(iter(report["files"]))
    partial = {
        "schemaVersion": report.get("schemaVersion", "1.0"),
        "thresholds": report.get("thresholds", {"high": 80, "low": 60}),
        "files": {first_file: report["files"][first_file]},
    }

    score = stryker.compute_mutation_score(partial)
    assert isinstance(score, float)
