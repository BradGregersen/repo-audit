"""``build_top_findings`` — Python-authored Top-N → ``TopFinding`` boundary list.

SYN-02 / D-18-09 / D-18-10 / D-69. Maps the ordered ``(token, finding,
PriorityScore | None)`` triples ``run_synthesis`` returns (``top_findings_data``)
into the agent-boundary :class:`~repo_audit.agent.schema.TopFinding` model.

PYTHON IS AUTHORITATIVE for every field EXCEPT ``why_it_matters`` (D-69):
``rank`` (1-based position in the already-ranked, already-selected list),
``finding_ref`` (``build_finding_ref`` — the canonical composite),
``file``/``line`` (off the Finding), ``severity``/``confidence`` (off the
Finding's post-verification rung), ``composite``/``band``/``dominant_driver``
(off the paired PriorityScore). ``why_it_matters`` is left "" for the agent to
fill — and even then it passes the faithfulness gate at render time.

THREAT T-18-08: this function NEVER reads an agent-supplied rank/score/id — the
Top-N numbers are computed by the deterministic stage and are authoritative. An
agent that reorders or rescores is ignored because those fields are re-authored
here from the Python list, not read back from the agent.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from repo_audit.agent.schema import TopFinding
from repo_audit.verification.record import build_finding_ref

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding
    from repo_audit.synthesis.record import PriorityScore


def build_top_findings(
    top_findings_data: "list[tuple[int, Finding, PriorityScore | None]]",
) -> list[TopFinding]:
    """Map the ranked/selected ``(token, finding, score)`` triples to ``TopFinding``.

    ``top_findings_data`` is the ordered output of ``run_synthesis``/``select_top_n``
    (descending priority, already eligibility-filtered + capped — never padded).
    ``rank`` is the 1-based position in THIS list (the selection is authoritative
    about order; rank is not read from anywhere else). ``why_it_matters`` is left
    empty for the agent to fill per item.

    Never raises on a missing score: a ``None`` PriorityScore (a finding that was
    selected but somehow unscored) yields neutral magnitudes (composite 0.0,
    band 0, empty driver) — the item still links its real finding.
    """
    out: list[TopFinding] = []
    for rank, (_token, finding, score) in enumerate(top_findings_data, start=1):
        composite = float(getattr(score, "composite", 0.0) or 0.0) if score else 0.0
        band = int(getattr(score, "band", 0) or 0) if score else 0
        dominant_driver = (
            str(getattr(score, "dominant_driver", "") or "") if score else ""
        )
        out.append(
            TopFinding(
                rank=rank,
                finding_ref=build_finding_ref(finding),
                file=getattr(finding, "file", None),
                line=getattr(finding, "line", None),
                severity=getattr(finding, "severity"),
                confidence=getattr(finding, "confidence"),
                composite=composite,
                band=band,
                dominant_driver=dominant_driver,
                why_it_matters="",
            )
        )
    return out


__all__ = ["TopFinding", "build_top_findings"]
