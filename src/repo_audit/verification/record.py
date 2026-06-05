"""Sidecar verification-record models — the auditable corroboration/refutation trail.

WHY A SIDECAR, NOT Finding FIELDS (RESEARCH §"Why a sidecar, not Finding fields"):
``Finding`` is ``ConfigDict(extra='forbid')`` and SCH-08-locked
(``test_finding_forbids_secret_value_field`` asserts no value-carrying fields).
Adding ``corroboration_tier`` / ``refutation`` to ``Finding`` would risk that
test and re-run its validators on every ``model_copy``. Instead the verification
trail is carried OUT-OF-BAND in a ``VerificationRecord`` keyed by a finding
fingerprint (``build_finding_ref``). ``Finding`` is never touched.

Every model is ``ConfigDict(extra='forbid')`` (D-03 boundary-model discipline,
mirrored from ``agent/schema.py``): an unknown field at construction or JSON
deserialization raises ``ValidationError`` before the object exists, so a
malformed sidecar cannot smuggle fields past the boundary.

``Citation.kind == "sibling_ref"`` (with ``sibling_finding_ref``) makes the
D-17-13 duplicate refutation angle structurally citable — a finding can be
refuted as a duplicate of another by pointing at the sibling's fingerprint.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding


# Citation kinds. ``sibling_ref`` is the D-17-13 carrier for the duplicate angle.
CitationKind = Literal["file_line", "lockfile", "policy", "sibling_ref"]

# The five refutation angles the critic may argue (RESEARCH §"Model set").
RefutationAngle = Literal[
    "upstream_guard",
    "test_or_dead_code",
    "existing_control",
    "static_read_as_runtime",
    "duplicate",
]

# The corroboration tiers + signals a finding may be promoted on. ``none`` is the
# default (un-promoted). The two signals (``reachability``, ``runtime``) sit
# alongside the three structural tiers (``identity`` > ``locus`` > ``coarse``).
CorroborationTier = Literal[
    "identity",
    "locus",
    "coarse",
    "reachability",
    "runtime",
    "none",
]


class Citation(BaseModel):
    """A claimed citation backing a refutation.

    Exactly which field is meaningful depends on ``kind``:
      * ``file_line``  → ``file`` + ``line`` (a source location).
      * ``lockfile``   → ``lockfile_entry`` (a parseable lockfile coordinate).
      * ``policy``     → ``policy_ref`` (a recognized policy statement).
      * ``sibling_ref``→ ``sibling_finding_ref`` (another finding's fingerprint;
                          the D-17-13 duplicate angle).

    The deterministic citation validator (Plan 17-02) resolves the claimed
    citation against the real repo; an unresolvable citation is treated as
    uncited and the refutation is discarded.
    """

    model_config = ConfigDict(extra="forbid")

    kind: CitationKind
    file: str | None = None
    line: int | None = None
    lockfile_entry: str | None = None
    policy_ref: str | None = None
    sibling_finding_ref: str | None = None


class RefutationRecord(BaseModel):
    """A single critic refutation attempt + whether its citation resolved.

    ``citation_valid`` is set by the deterministic validator (Plan 17-02), NOT by
    the LLM — the LLM is advisory, Python is authoritative (D-69 precedent). An
    invalid-citation refutation is DISCARDED (logged into
    ``VerificationRecord.discarded_refutations``), never applied.
    """

    model_config = ConfigDict(extra="forbid")

    angle: RefutationAngle
    citation: Citation
    reason: str
    citation_valid: bool


class VerificationRecord(BaseModel):
    """The per-finding sidecar trail, keyed by ``finding_ref`` (build_finding_ref).

    Carries the winning corroboration tier, the source_tools that corroborated,
    the tri-state reachability signal (None = downgrade-safe unknown), whether the
    critic ran, the surviving refutation (if any), the discarded refutations, and
    the final confidence rung. Nothing here mutates ``Finding`` — it is a parallel
    record consumed by the stage + renderer.
    """

    model_config = ConfigDict(extra="forbid")

    finding_ref: str = Field(..., min_length=1)
    # The per-finding IDENTITY token (17-04): a zero-based index assigned once over
    # the INPUT finding list. ``finding_ref`` (build_finding_ref) is NON-unique —
    # two findings from the same tool at the same locus collide on it — so it can
    # no longer be the verdict/tier dispatch key. ``candidate_token`` IS that key:
    # it survives the deterministic (finding,record) re-sort (stamped BEFORE the
    # sort), so the finding↔record pairing carries identity even when the finding's
    # list position changes. ``finding_ref`` stays the display/citation string.
    candidate_token: int = Field(default=-1)
    corroboration_tier: CorroborationTier = "none"
    corroborated_by: list[str] = Field(default_factory=list)
    reachable: bool | None = None
    critic_ran: bool = False
    refutation: RefutationRecord | None = None
    discarded_refutations: list[RefutationRecord] = Field(default_factory=list)
    final_confidence: str = ""


def build_finding_ref(finding: "Finding") -> str:
    """Return the canonical composite fingerprint for ``finding``.

    Shape: ``"{source_tool}::{rule_id}::{file}:{line}"`` with empty-string
    fallbacks for None. This is the SAME composite the render-time dispute log
    builds (``render/corroboration.py`` L83-87) and ``SeverityCall.finding_ref``
    references — one canonical key so the sidecar, the renderer, and the agent
    boundary all collide on the same string for the same finding.
    """
    source_tool = getattr(finding, "source_tool", "") or ""
    rule_id = getattr(finding, "rule_id", "") or ""
    file = getattr(finding, "file", "") or ""
    line = getattr(finding, "line", "")
    line_str = "" if line is None else str(line)
    return f"{source_tool}::{rule_id}::{file}:{line_str}"


__all__ = [
    "Citation",
    "CitationKind",
    "RefutationRecord",
    "RefutationAngle",
    "VerificationRecord",
    "CorroborationTier",
    "build_finding_ref",
]
