"""Lighthouse LHR JSON → aggregate web-perf Finding(s) (PERF-01, Plan 15-03).

A tiny, dedicated transform — NOT a fork of ``sarif_to_findings`` (Lighthouse
emits no SARIF). The Lighthouse Result (LHR) document carries
``categories.performance.score`` plus an ``audits`` map of per-metric numeric
values. This module collapses the LHR to **exactly ONE aggregate**
``lighthouse_perf_summary`` Finding (NOT one-per-audit — a single page's perf is
one quality signal, mirroring the jscpd / lcov single-aggregate model in
``adapters/architecture/jscpd_json.py``), and conditionally appends TWO
INDEPENDENT trigger findings:

  * ``web_transfer_oversized`` — fires when ``web_transfer_bytes`` (the
    ``total-byte-weight`` carrier) exceeds ``config.web_budget_bytes``.
  * ``web_transfer_regression`` — fires ONLY when a ``prior_web_bytes`` baseline
    is supplied AND the growth exceeds BOTH ``config.regression_pct`` (% gate) AND
    ``config.regression_floor_bytes`` (byte floor). No prior → no regression
    finding (a baseline run). The two triggers are INDEPENDENT — a doc can fire
    oversized, regression, both, or neither.

The carrier key ``web_transfer_bytes`` in the summary's ``parsed_value`` is the
metric source Plan 04's cross-scan trend/delta reads (this module only measures
the CURRENT page; the cross-scan regression delta is Plan 04's, but the
prior-passed-in regression finding fires here when given).

Contract (RESEARCH §"Pattern 3", §"Finding Shapes & Severity Ladders"):
  * ``dimension="quality"`` (the PUBLIC dimension token — PATTERNS §Dimension
    token; the adapter.yaml block-level ``quality_debt`` is the routing default).
  * Summary severity: ``info`` default; ``minor`` when ``perf_score`` < the
    configurable half-mark (0.5). The ladder TOPS at ``major`` (oversized /
    regression are ``minor``), so the SCH-04 candidate cap (which bites only at
    critical/blocker) is NEVER tripped — the faithful severity is preserved in
    ``parsed_value['faithful_severity']``.
  * ``evidence_type="runtime"`` (a live headless-Chrome page load — the deep web
    perf tier), ``confidence="candidate"`` (D-06-03; Phase 17 corroboration is the
    SOLE promotion path — ``runtime`` is orthogonal to confidence and does NOT
    promote, D-15-07), ``file=None``, ``line=None``, ``source_tool="lighthouse"``.
  * VERIFY-PHRASING (D-15-07 runtime-exemption trap): every recommendation
    CONTAINS "verify" and contains NONE of ``enforced`` / ``secure`` /
    ``protected``. SELF-ENFORCED here — the shared CRIT-4 ``assert_verify_phrasing``
    tripwire EXEMPTS ``evidence_type == "runtime"``, so it would silently pass an
    overclaiming finding; this module must police itself (it does NOT call
    ``assert_verify_phrasing``).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from repo_audit.schema.finding import Evidence, Finding

if TYPE_CHECKING:
    from repo_audit.adapters.quality_depth.config import QualityDepthConfig

_SOURCE_TOOL = "lighthouse"
_SOURCE_COLLECTOR = "quality_depth"
_DEFAULT_DIMENSION = "quality"

_RULE_ID_SUMMARY = "lighthouse_perf_summary"
_RULE_ID_OVERSIZED = "web_transfer_oversized"
_RULE_ID_REGRESSION = "web_transfer_regression"

# perf_score below this → the summary is `minor` instead of `info` (configurable
# only via this module constant; the budgets/regression knobs live in config).
_MINOR_SCORE_THRESHOLD: float = 0.5

# The aggregate-summary recommendation. Says "verify"; carries NO runtime-certainty
# word (enforced/secure/protected) — self-enforced (the D-15-07 trap).
_SUMMARY_RECOMMENDATION: str = (
    "Lighthouse measured these web performance metrics on a live page load — "
    "verify the LCP / CLS / TBT figures and the total transfer size against a "
    "warm-cache repeat run before acting; a single cold run reflects network "
    "conditions, not only the app."
)

_OVERSIZED_RECOMMENDATION: str = (
    "The measured web transfer size exceeds the configured budget — verify the "
    "payload breakdown (Lighthouse total-byte-weight) and confirm whether large "
    "assets can be trimmed or lazy-loaded before treating this as a regression."
)

_REGRESSION_RECOMMENDATION: str = (
    "The web transfer size grew past the configured growth threshold versus the "
    "prior scan — verify the size delta is real (not a one-off measurement) by "
    "comparing the asset breakdown across the two runs before attributing it."
)


def _audit_numeric(audits: dict[str, Any], key: str) -> float | None:
    """Return ``audits[key].numericValue`` as a float, or ``None`` when absent."""
    audit = audits.get(key)
    if not isinstance(audit, dict):
        return None
    value = audit.get("numericValue")
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _summary_severity(perf_score: float | None) -> str:
    """``minor`` when perf_score < 0.5, else ``info``. Tops at major-safe (minor)."""
    if perf_score is not None and perf_score < _MINOR_SCORE_THRESHOLD:
        return "minor"
    return "info"


def _make_finding(
    *,
    dimension: str,
    severity: str,
    rule_id: str,
    recommendation: str,
    parsed_value: dict[str, Any],
    snippet: str,
) -> Finding:
    """Construct one runtime/candidate quality Finding (the shared shape)."""
    return Finding(
        dimension=dimension,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        file=None,
        line=None,
        evidence=Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=snippet,
            parsed_value=parsed_value,
        ),
        evidence_type="runtime",
        confidence="candidate",
        recommendation=recommendation,
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_COLLECTOR,
        rule_id=rule_id,
        confidence_caveat=None,
    )


def map_lighthouse_json(
    lhr: dict[str, Any],
    *,
    config: "QualityDepthConfig | None" = None,
    default_dimension: str = _DEFAULT_DIMENSION,
    prior_web_bytes: int | None = None,
) -> list[Finding]:
    """Collapse an LHR document to its aggregate perf Finding(s).

    Args:
        lhr: the parsed Lighthouse Result JSON
            (``{categories:{performance:{score}}, audits:{...numericValue...}}``).
        config: the resolved :class:`QualityDepthConfig` supplying
            ``web_budget_bytes`` / ``regression_pct`` / ``regression_floor_bytes``.
            ``None`` → the documented defaults (the alias path).
        default_dimension: the routed dimension (``quality`` by default — the
            PUBLIC token; resolved from ``adapter.yaml`` by the caller).
        prior_web_bytes: an optional prior-scan ``web_transfer_bytes`` baseline.
            When given AND growth exceeds BOTH gates, a ``web_transfer_regression``
            finding is appended. ``None`` (a baseline run) → no regression finding.

    Returns:
        ``[]`` when the LHR carries no ``total-byte-weight`` numeric (no usable
        carrier); otherwise a list whose FIRST element is the single aggregate
        ``lighthouse_perf_summary`` Finding, optionally followed by an INDEPENDENT
        ``web_transfer_oversized`` and/or ``web_transfer_regression`` Finding.
        NEVER raises across the boundary.
    """
    if config is None:
        # Local import avoids a module-load cycle (config imports nothing from here,
        # but keep the dependency lazy + consistent with the TYPE_CHECKING import).
        from repo_audit.adapters.quality_depth.config import QualityDepthConfig

        config = QualityDepthConfig()

    lhr = lhr or {}
    audits = lhr.get("audits") or {}
    transfer = _audit_numeric(audits, "total-byte-weight")
    if transfer is None:
        # No carrier metric — nothing to summarize.
        return []

    web_transfer_bytes = int(transfer)
    perf_cat = (lhr.get("categories") or {}).get("performance") or {}
    perf_score = perf_cat.get("score")
    try:
        perf_score = float(perf_score) if perf_score is not None else None
    except (TypeError, ValueError):
        perf_score = None

    lcp = _audit_numeric(audits, "largest-contentful-paint")
    cls = _audit_numeric(audits, "cumulative-layout-shift")
    tbt = _audit_numeric(audits, "total-blocking-time")

    severity = _summary_severity(perf_score)
    findings: list[Finding] = [
        _make_finding(
            dimension=default_dimension,
            severity=severity,
            rule_id=_RULE_ID_SUMMARY,
            recommendation=_SUMMARY_RECOMMENDATION,
            parsed_value={
                "web_transfer_bytes": web_transfer_bytes,
                "lcp_ms": int(lcp) if lcp is not None else None,
                "cls": cls,
                "tbt_ms": int(tbt) if tbt is not None else None,
                "perf_score": perf_score,
                "faithful_severity": severity,
            },
            snippet=(
                f"lighthouse: perf score {perf_score}, "
                f"transfer {web_transfer_bytes} bytes, "
                f"LCP {int(lcp) if lcp is not None else '?'}ms"
            ),
        )
    ]

    # INDEPENDENT trigger 1 — oversized transfer (vs the configured budget).
    if web_transfer_bytes > config.web_budget_bytes:
        findings.append(
            _make_finding(
                dimension=default_dimension,
                severity="minor",
                rule_id=_RULE_ID_OVERSIZED,
                recommendation=_OVERSIZED_RECOMMENDATION,
                parsed_value={
                    "web_transfer_bytes": web_transfer_bytes,
                    "web_budget_bytes": config.web_budget_bytes,
                    "faithful_severity": "minor",
                },
                snippet=(
                    f"lighthouse: transfer {web_transfer_bytes} bytes "
                    f"> budget {config.web_budget_bytes}"
                ),
            )
        )

    # INDEPENDENT trigger 2 — regression (ONLY with a prior, past BOTH gates).
    if prior_web_bytes is not None and prior_web_bytes > 0:
        growth_bytes = web_transfer_bytes - prior_web_bytes
        growth_pct = (growth_bytes / prior_web_bytes) * 100.0
        if (
            growth_pct > config.regression_pct
            and growth_bytes > config.regression_floor_bytes
        ):
            findings.append(
                _make_finding(
                    dimension=default_dimension,
                    severity="minor",
                    rule_id=_RULE_ID_REGRESSION,
                    recommendation=_REGRESSION_RECOMMENDATION,
                    parsed_value={
                        "web_transfer_bytes": web_transfer_bytes,
                        "prior_web_bytes": prior_web_bytes,
                        "growth_bytes": growth_bytes,
                        "growth_pct": round(growth_pct, 2),
                        "regression_pct": config.regression_pct,
                        "regression_floor_bytes": config.regression_floor_bytes,
                        "faithful_severity": "minor",
                    },
                    snippet=(
                        f"lighthouse: transfer grew {growth_bytes} bytes "
                        f"(+{growth_pct:.1f}%) vs prior {prior_web_bytes}"
                    ),
                )
            )

    return findings


def map_lighthouse_lhr(lhr: dict[str, Any]) -> list[Finding]:
    """Alias the Plan-01 runtime-verify-phrasing scaffold calls (defaults config).

    The ``test_runtime_verify_phrasing.py`` scaffold invokes ``map_lighthouse_lhr``
    with only the document; this thin delegate supplies the documented-default
    config so the D-15-07 self-enforcement assertions run on the aggregate finding.
    Kept in lockstep with :func:`map_lighthouse_json`.
    """
    return map_lighthouse_json(lhr)


__all__ = [
    "map_lighthouse_json",
    "map_lighthouse_lhr",
]
