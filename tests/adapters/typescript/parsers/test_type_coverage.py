"""TST-03 (type-coverage) — any-density parser contract (Plan 11-01 Wave 0).

SKIPPED until the Wave-1
``repo_audit.adapters.typescript.parsers.type_coverage_json`` module
lands, then activates automatically.

type-coverage's ``--json-output`` is a BOOLEAN flag (11-RESEARCH Pitfall 10): the
JSON carries ``correctCount``/``totalCount``/``anys`` with NO pre-computed
percentage. The parser DERIVES:

    type_coverage_pct = 100 * correctCount / totalCount
    any_density       = 1 - correctCount / totalCount

The fixture (950/1000) yields type_coverage_pct = 95.0 and any_density = 0.05.
The parser emits ONE aggregate Finding (mirrors the lcov/kover aggregate shape).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

tc = pytest.importorskip(
    "repo_audit.adapters.typescript.parsers.type_coverage_json",
    reason="Wave 1 (plan 11-04) not yet landed — parsers.type_coverage_json missing",
)

_FIXTURE = Path(__file__).parent / "fixtures" / "type-coverage.json"


def _load() -> dict:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _build_finding():
    """Build the aggregate Finding via whichever Wave-1 entry-point seam exists.

    Prefers a dict-taking builder (``build_finding`` / ``findings_from_json`` /
    ``parse_type_coverage``); the test feeds the loaded fixture dict directly so
    no live ``npx type-coverage`` invocation is needed.
    """
    report = _load()
    for name in ("build_finding", "parse_type_coverage", "findings_from_json"):
        fn = getattr(tc, name, None)
        if fn is None:
            continue
        out = fn(report)
        return out[0] if isinstance(out, (list, tuple)) else out
    raise AssertionError(
        "type_coverage_json exposes no recognised dict->Finding entry point"
    )


def test_any_density_finding():
    """One aggregate Finding: any_density == 0.05, type_coverage_pct == 95.0."""
    f = _build_finding()

    assert f.dimension in {"correctness", "quality"}
    assert f.evidence.parsed_value["any_density"] == 0.05
    assert f.evidence.parsed_value["type_coverage_pct"] == 95.0
