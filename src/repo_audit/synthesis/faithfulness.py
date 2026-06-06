"""Synthesis-side faithfulness helpers — the Top-N narration fold (SYN-02, D-64).

Thin, dependency-light surface over the render-layer faithfulness gate
(``render/faithfulness.py``), purpose-built for the ``why_it_matters`` prose the
agent supplies per :class:`~repo_audit.agent.schema.TopFinding`.

THE CONTRACT (T-18-09): a ``why_it_matters`` sentence citing a TopFinding's
``composite`` / factor magnitude / ``epss`` SURVIVES the faithfulness gate; a
sentence citing a number NOT in that synthesis-derived allow-set is STRIPPED
(the negative control). ``build_allowed_numbers`` in the render layer folds the
SAME magnitudes into the report-wide AllowedNumbers set at render time — this
module is the unit-testable, finding-store-free view of that fold so the SC3
proof is independent of a full ScanReport.

``allowed_numbers_for_score`` builds the allow-set for a single (composite, the
four factor weights, epss) tuple; ``strip_unfaithful_numbers`` runs the D-64
sentence-level strip over a prose string against that allow-set.
"""
from __future__ import annotations

from repo_audit.render.faithfulness import (
    check_faithfulness,
    load_faithfulness_allowlist,
)

# D-62 small-cardinals seed (narrative-phrasing freedom 0..7) — mirrors the
# render-layer seed so a bare "1" / "2" in why_it_matters never strips.
_SMALL_CARDINALS: set[float] = {float(i) for i in range(8)}


def allowed_numbers_for_score(
    *,
    composite: float | None = None,
    severity_w: float | None = None,
    confidence_w: float | None = None,
    exploitability_w: float | None = None,
    blast_radius_w: float | None = None,
    epss: float | None = None,
    rank: int | None = None,
    band: int | None = None,
) -> set[float]:
    """Build the synthesis allow-set for ONE TopFinding's deterministic numbers.

    Folds the composite (raw + 2-decimal display form), the four factor
    magnitudes, the optional epss multiplier, and the rank/band — exactly the
    magnitudes ``render/faithfulness._fold_top_findings`` admits report-wide.
    Seeds the 0..7 small-cardinals so phrasing freedom survives.
    """
    allowed: set[float] = set(_SMALL_CARDINALS)
    for magnitude in (
        composite,
        severity_w,
        confidence_w,
        exploitability_w,
        blast_radius_w,
        epss,
    ):
        if magnitude is not None:
            try:
                val = float(magnitude)
            except (TypeError, ValueError):
                continue
            allowed.add(val)
            allowed.add(round(val, 2))
    if rank is not None:
        allowed.add(float(rank))
    if band is not None:
        allowed.add(float(band))
    return allowed


def strip_unfaithful_numbers(prose: str, allowed: set[float]) -> str:
    """Run the D-64 sentence-level strip over ``prose`` against ``allowed``.

    Returns the cleaned prose: sentences whose numeric tokens all trace back to
    ``allowed`` (within the D-62 5% tolerance) are kept; a sentence carrying an
    untraceable number is stripped (replaced by the D-63 collapse marker). The
    render-layer ``check_faithfulness`` is the single implementation — this is
    just the synthesis-facing call with the packaged regex pair.
    """
    trigger, allowlist = load_faithfulness_allowlist()
    cleaned, _violations = check_faithfulness(prose, allowed, trigger, allowlist)
    return cleaned


__all__ = ["allowed_numbers_for_score", "strip_unfaithful_numbers"]
