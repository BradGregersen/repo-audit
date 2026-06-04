"""RN bundle byte size → aggregate static size Finding(s) (PERF-01, Plan 15-03).

A tiny, dedicated transform mirroring the jscpd / lcov single-aggregate model
(``adapters/architecture/jscpd_json.py``): a measured ``rn_bundle_bytes`` integer
collapses to **exactly ONE aggregate** ``rn_bundle_size_summary`` Finding, plus TWO
INDEPENDENT trigger findings:

  * ``rn_bundle_oversized`` — fires when ``rn_bundle_bytes`` exceeds
    ``config.rn_budget_bytes``.
  * ``rn_bundle_regression`` — fires ONLY when a ``prior_rn_bytes`` baseline is
    supplied AND the growth exceeds BOTH ``config.regression_pct`` (% gate) AND
    ``config.regression_floor_bytes`` (byte floor). No prior → no regression
    finding (a baseline run). The two triggers are INDEPENDENT.

Contract (RESEARCH §"Finding Shapes & Severity Ladders"):
  * ``dimension="quality"`` (the PUBLIC dimension token).
  * ``evidence_type="static"`` — a MEASURED ARTIFACT (a stat()'d ``.bundle``), NOT
    a runtime page load (the lighthouse sibling is ``runtime``; RN bundle size is
    a static file measurement). This is the D-15 disposition: the RN bundle stays
    ``static`` while lighthouse is ``runtime``.
  * Severity: ``info`` summary; ``minor`` oversized / regression. The ladder TOPS
    at ``major`` (never reached here), so the SCH-04 candidate cap (critical/blocker
    only) is NEVER tripped. ``confidence="candidate"``, ``source_tool="metro"``.
  * VERIFY-PHRASING: every recommendation CONTAINS "verify" and contains NONE of
    ``enforced`` / ``secure`` / ``protected`` (self-enforced; SAFE-05).

The carrier key ``rn_bundle_bytes`` in the summary's ``parsed_value`` is the metric
source Plan 04's cross-scan trend/delta reads (this module measures the CURRENT
bundle only; the prior-passed-in regression finding fires here when given).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from repo_audit.schema.finding import Evidence, Finding

if TYPE_CHECKING:
    from repo_audit.adapters.quality_depth.config import QualityDepthConfig

_SOURCE_TOOL = "metro"
_SOURCE_COLLECTOR = "quality_depth"
_DEFAULT_DIMENSION = "quality"

_RULE_ID_SUMMARY = "rn_bundle_size_summary"
_RULE_ID_OVERSIZED = "rn_bundle_oversized"
_RULE_ID_REGRESSION = "rn_bundle_regression"

_SUMMARY_RECOMMENDATION: str = (
    "This is the measured production React-Native JS bundle size — verify it "
    "against your release artifact (`--dev false`) and a prior build before "
    "treating any change as significant; a debug bundle is much larger and not "
    "comparable."
)

_OVERSIZED_RECOMMENDATION: str = (
    "The measured RN bundle exceeds the configured size budget — verify the "
    "module breakdown (e.g. a source-map explorer) and confirm whether large "
    "dependencies can be trimmed or code-split before acting."
)

_REGRESSION_RECOMMENDATION: str = (
    "The RN bundle grew past the configured growth threshold versus the prior "
    "scan — verify the size delta is a real, sustained increase (not a one-off "
    "build difference) by comparing the module breakdown across the two runs."
)


def _make_finding(
    *,
    dimension: str,
    severity: str,
    rule_id: str,
    recommendation: str,
    parsed_value: dict[str, Any],
    snippet: str,
) -> Finding:
    """Construct one static/candidate quality Finding (the shared shape)."""
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
        evidence_type="static",
        confidence="candidate",
        recommendation=recommendation,
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_COLLECTOR,
        rule_id=rule_id,
        confidence_caveat=None,
    )


def map_rn_bundle_bytes(
    rn_bundle_bytes: int,
    *,
    config: "QualityDepthConfig | None" = None,
    default_dimension: str = _DEFAULT_DIMENSION,
    prior_rn_bytes: int | None = None,
) -> list[Finding]:
    """Collapse a measured RN bundle byte size to its aggregate Finding(s).

    Args:
        rn_bundle_bytes: the measured production bundle size in bytes (a ``stat``
            of the ``.bundle`` artifact — existing or freshly built).
        config: the resolved :class:`QualityDepthConfig` supplying
            ``rn_budget_bytes`` / ``regression_pct`` / ``regression_floor_bytes``.
            ``None`` → the documented defaults.
        default_dimension: the routed dimension (``quality`` by default).
        prior_rn_bytes: an optional prior-scan ``rn_bundle_bytes`` baseline. When
            given AND growth exceeds BOTH gates, a ``rn_bundle_regression`` finding
            is appended. ``None`` (a baseline run) → no regression finding.

    Returns:
        A list whose FIRST element is the single aggregate
        ``rn_bundle_size_summary`` Finding (always present), optionally followed by
        an INDEPENDENT ``rn_bundle_oversized`` and/or ``rn_bundle_regression``
        Finding. NEVER raises.
    """
    if config is None:
        from repo_audit.adapters.quality_depth.config import QualityDepthConfig

        config = QualityDepthConfig()

    rn_bundle_bytes = int(rn_bundle_bytes)
    findings: list[Finding] = [
        _make_finding(
            dimension=default_dimension,
            severity="info",
            rule_id=_RULE_ID_SUMMARY,
            recommendation=_SUMMARY_RECOMMENDATION,
            parsed_value={
                "rn_bundle_bytes": rn_bundle_bytes,
                "faithful_severity": "info",
            },
            snippet=f"metro: production RN bundle {rn_bundle_bytes} bytes",
        )
    ]

    # INDEPENDENT trigger 1 — oversized (vs the configured budget).
    if rn_bundle_bytes > config.rn_budget_bytes:
        findings.append(
            _make_finding(
                dimension=default_dimension,
                severity="minor",
                rule_id=_RULE_ID_OVERSIZED,
                recommendation=_OVERSIZED_RECOMMENDATION,
                parsed_value={
                    "rn_bundle_bytes": rn_bundle_bytes,
                    "rn_budget_bytes": config.rn_budget_bytes,
                    "faithful_severity": "minor",
                },
                snippet=(
                    f"metro: bundle {rn_bundle_bytes} bytes "
                    f"> budget {config.rn_budget_bytes}"
                ),
            )
        )

    # INDEPENDENT trigger 2 — regression (ONLY with a prior, past BOTH gates).
    if prior_rn_bytes is not None and prior_rn_bytes > 0:
        growth_bytes = rn_bundle_bytes - prior_rn_bytes
        growth_pct = (growth_bytes / prior_rn_bytes) * 100.0
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
                        "rn_bundle_bytes": rn_bundle_bytes,
                        "prior_rn_bytes": prior_rn_bytes,
                        "growth_bytes": growth_bytes,
                        "growth_pct": round(growth_pct, 2),
                        "regression_pct": config.regression_pct,
                        "regression_floor_bytes": config.regression_floor_bytes,
                        "faithful_severity": "minor",
                    },
                    snippet=(
                        f"metro: bundle grew {growth_bytes} bytes "
                        f"(+{growth_pct:.1f}%) vs prior {prior_rn_bytes}"
                    ),
                )
            )

    return findings


__all__ = ["map_rn_bundle_bytes"]
