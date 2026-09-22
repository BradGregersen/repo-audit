"""TST-01 (kover) — JaCoCo-XML coverage parser contract (Plan 11-01 Wave 0).

SKIPPED until the Wave-1
``repo_audit.adapters.typescript.parsers.kover_xml`` module lands, then
activates automatically.

kover's ``koverXmlReport`` emits JaCoCo-format XML, NOT lcov (11-RESEARCH
Pitfall 9). The parser MUST read the REPORT-ROOT ``<counter type="LINE">`` (the
whole-project total), not a nested ``<package>`` counter (RESEARCH Assumption
A3). The fixture deliberately gives the root LINE counter (80 covered / 20
missed -> 80.0%) DIFFERENT numbers from the nested package LINE counter (7
covered / 13 missed -> 35.0%) so a parser that walks into the package counter
fails this test.

The fixture carries NO DOCTYPE/entities, so it parses cleanly through
``safe_xml.parse_xml`` (defusedxml) — the XXE-safe seam the kover parser is
contractually bound to (threat T-11-01-01).

The kover parser mirrors the lcov parser's aggregate-Finding shape
(``parsers/lcov.py``): one ``test_integrity`` Finding per scan whose
``parsed_value`` carries ``line_pct``/``branch_pct``/``function_pct``. Its
default report path is ``build/reports/kover/report.xml`` (Pitfall 9). The test
exercises whichever entry point the Wave-1 module exposes — a direct
XML-path helper if present, else the lcov-style ``parse_from_repo(repo_path)``
against a staged ``build/reports/kover/report.xml``.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

kover = pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.kover_xml",
    reason="optional module repo_audit.adapters.typescript.parsers.kover_xml not importable — feature not present in this build, or the install is incomplete",
)

_FIXTURE = Path(__file__).parent / "fixtures" / "kover-report.xml"
_KOVER_RELATIVE = "build/reports/kover/report.xml"


def _parse(target_xml: Path, repo_root: Path):
    """Call the kover parser via whichever entry-point seam Wave 1 exposes.

    Prefers a direct XML-path helper (``parse_xml_report`` /
    ``parse_from_repo_xml`` / ``parse_kover_xml``); falls back to the lcov-style
    ``parse_from_repo(repo_root)`` which reads ``build/reports/kover/report.xml``.
    """
    for name in ("parse_xml_report", "parse_from_repo_xml", "parse_kover_xml"):
        fn = getattr(kover, name, None)
        if fn is not None:
            return fn(target_xml)
    return kover.parse_from_repo(repo_root)


def _staged_repo(tmp_path: Path, src_xml: Path | None) -> Path:
    """Build a repo dir with the kover report staged at its conventional path."""
    dest = tmp_path / _KOVER_RELATIVE
    if src_xml is not None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src_xml, dest)
    return tmp_path


def test_kover_xml_line_pct_from_report_root(tmp_path):
    """Exactly one test_integrity Finding with line_pct from the REPORT-ROOT counter."""
    # Parse the STAGED COPY, never the source fixture. ``parse_kover_xml``
    # applies a 24h staleness gate to the artifact's mtime and returns an
    # ``unavailable`` Finding — which carries no ``line_pct`` — for anything
    # older. A checked-in fixture's mtime is its checkout time, so pointing the
    # parser at it makes this test pass only on a clone less than a day old.
    # ``_staged_repo`` copies with ``shutil.copyfile``, which does NOT preserve
    # mtime, so the staged copy is always fresh: the staleness gate is exercised
    # for real rather than bypassed, and the result no longer depends on how long
    # ago the repo was cloned.
    repo = _staged_repo(tmp_path, _FIXTURE)
    staged_xml = repo / _KOVER_RELATIVE
    findings = _parse(staged_xml, repo)

    assert len(findings) == 1
    f = findings[0]
    assert f.dimension == "test_integrity"
    # report-root LINE = 80 covered / 20 missed -> 80.0 (NOT the nested 35.0).
    assert f.evidence.parsed_value["line_pct"] == 80.0


def test_kover_missing_artifact_unavailable(tmp_path):
    """A non-existent kover report path -> one unavailable Finding, no raise."""
    missing_xml = tmp_path / "absent" / "report.xml"
    repo = _staged_repo(tmp_path, None)  # no report staged
    findings = _parse(missing_xml, repo)

    assert len(findings) == 1
    assert findings[0].evidence_type == "unavailable"
