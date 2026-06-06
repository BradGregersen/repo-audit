"""The `PriorityScore` sidecar — the per-finding priority record.

WHY A SIDECAR, NOT Finding FIELDS (mirrors verification/record.py verbatim):
``Finding`` is ``ConfigDict(extra='forbid')`` and SCH-08-locked
(``test_finding_forbids_secret_value_field`` asserts no value-carrying fields).
Adding ``composite`` / ``epss`` / ``band`` to ``Finding`` would risk that test
and re-run its validators on every ``model_copy``. Instead the priority is
carried OUT-OF-BAND in a ``PriorityScore`` keyed by the per-finding identity.
``Finding`` is never touched.

THE candidate_token IS THE DISPATCH KEY (the 17-04 lesson, re-stated verbatim):
``finding_ref`` (build_finding_ref) is NON-unique — two findings from the same
tool at the same locus collide on it — so it can NOT be the score dispatch key.
``candidate_token`` IS that key: a zero-based index assigned once over the INPUT
finding list, stamped BEFORE any deterministic (finding, score) re-sort, so the
finding↔score pairing carries identity even when the finding's list position
changes. ``finding_ref`` stays the display/citation string only. Dispatching the
score map on ``candidate_token`` (never ``finding_ref``) is what keeps two
collision findings holding DISTINCT scores (``test_collision_findings_keep_distinct_scores``).

``ConfigDict(extra='forbid')`` (D-03 boundary-model discipline): an unknown field
at construction or JSON deserialization raises ``ValidationError`` before the
object exists, so a malformed sidecar cannot smuggle fields past the boundary.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PriorityScore(BaseModel):
    """The per-finding priority sidecar, paired to its finding by ``candidate_token``.

    Carries the four factor weights, the multiplicative ``composite``, the
    raise-only EPSS multiplier (None = neutral/absent), the KEV ``band`` (1 = KEV
    top-band), and the ``dominant_driver`` (the name of the largest factor). The
    score NEVER mutates ``Finding`` — it is a parallel record consumed by the
    ranking + selection + render stages.
    """

    model_config = ConfigDict(extra="forbid")

    finding_ref: str = Field(default="")
    # The dispatch IDENTITY (17-04): zero-based input index. NEVER finding_ref.
    candidate_token: int = Field(default=-1)

    severity_w: float = 0.0
    confidence_w: float = 0.0
    exploitability_w: float = 0.0
    blast_radius_w: float = 0.0

    composite: float = 0.0
    epss: float | None = None
    kev: bool = False
    band: int = 0
    dominant_driver: str = ""


__all__ = ["PriorityScore"]
