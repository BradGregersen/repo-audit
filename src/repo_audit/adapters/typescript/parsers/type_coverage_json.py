"""type-coverage any-density parser (TST-03, Phase 11 Wave 1).

PURE PARSER. Reads an already-loaded ``type-coverage --json-output`` dict and
turns it into ONE aggregate Finding. It NEVER invokes ``type-coverage`` and
NEVER touches the filesystem.

11-RESEARCH Pitfall 10: ``--json-output`` is a BOOLEAN flag; the emitted JSON
carries ``correctCount`` / ``totalCount`` / ``anys`` with NO pre-computed
percentage. The parser DERIVES (D-11-08 any-density)::

    type_coverage_pct = round(100 * correctCount / totalCount, 1)
    any_density       = round(1 - correctCount / totalCount, 4)

The fixture (950 / 1000) → ``type_coverage_pct = 95.0`` and ``any_density = 0.05``.

The INVOCATION half (``npx type-coverage --json-output`` + the live-fixture
capture — RESEARCH A2 / Open Q2 around the exact output destination) lives in
Plan 05's run-step; this module is the unit-testable transform half.

The Finding is framed as a METRIC ("any-density: N"), never a verdict
("types are bad") — it reports the proportion of expressions whose type resolves
to ``any``, which is a quality/correctness signal, not a condemnation.
"""
from __future__ import annotations

from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "type-coverage"
_DIMENSION = "correctness"  # CONTEXT discretion: any-density leans correctness/quality


def parse_type_coverage(data: dict) -> list[Finding]:
    """Return the ONE aggregate any-density Finding (or an unavailable Finding).

    Always returns exactly one Finding so the Test/Quality section has a stable
    row count regardless of input:

        * missing / zero / non-numeric ``totalCount`` → ``evidence_type='unavailable'``
          (mirrors ``lcov._unavailable_finding``; never raises, never divides by zero).
        * valid counts → ``evidence_type='static'`` with ``type_coverage_pct`` +
          ``any_density`` + ``correct_count`` + ``total_count`` in ``parsed_value``.
    """
    correct = data.get("correctCount") if isinstance(data, dict) else None
    total = data.get("totalCount") if isinstance(data, dict) else None

    if not isinstance(correct, (int, float)) or not isinstance(total, (int, float)) or total <= 0:
        return [_unavailable_finding(detail=f"correctCount/totalCount missing or zero: {data!r}"[:512])]

    # D-11-08 derivation (the canonical form is any_density = 1 - data["correctCount"]
    # / data["totalCount"]); we operate on the validated `correct`/`total` locals so a
    # non-numeric / zero totalCount degrades to the unavailable Finding above rather
    # than raising a TypeError / ZeroDivisionError.
    pct = round(100.0 * correct / total, 1)
    any_density = round(1.0 - correct / total, 4)
    anys = data.get("anys")
    any_count = len(anys) if isinstance(anys, list) else None

    snippet = (
        f"type-coverage: {pct}% typed, any-density {any_density} "
        f"({int(total) - int(correct)} of {int(total)} expressions are any)"
    )

    return [
        Finding(
            dimension=_DIMENSION,
            severity="minor",
            evidence_type="static",
            confidence="candidate",
            source_tool=_SOURCE_TOOL,
            source_collector="typescript_adapter",
            rule_id="any_density",
            recommendation=(
                f"any-density: {any_density} (type-coverage {pct}%). The "
                "proportion of expressions whose type resolves to `any`; a "
                "higher density means more of the codebase escapes type "
                "checking. A metric, not a verdict — narrow the widest `any` "
                "hot-spots first."
            ),
            evidence=Evidence(
                tool="type-coverage-json",
                output_snippet=snippet,
                parsed_value={
                    "type_coverage_pct": pct,
                    "any_density": any_density,
                    "correct_count": int(correct),
                    "total_count": int(total),
                    "any_count": any_count,
                },
            ),
        )
    ]


def _unavailable_finding(*, detail: str) -> Finding:
    """Missing / zero / malformed type-coverage JSON ⇒ one unavailable Finding."""
    return Finding(
        dimension=_DIMENSION,
        severity="minor",
        evidence_type="unavailable",
        confidence="candidate",
        source_tool=_SOURCE_TOOL,
        source_collector="typescript_adapter",
        rule_id="any_density_unavailable",
        recommendation=(
            "Run `npx type-coverage --detail --json-output` to produce the "
            "type-coverage report so any-density can be computed."
        ),
        evidence=Evidence(
            tool="type-coverage-json",
            output_snippet=detail,
            parsed_value={"reason": "type_coverage_unavailable", "detail": detail},
        ),
    )


__all__ = ["parse_type_coverage"]
