"""Draft builder for ``repo-audit issues`` (Phase 19, Plan 19-02).

Turns a loaded ScanReport into the set of issue drafts the filer (Plan 03) will
later propose and create. This module owns CONTEXT decisions D-04, D-05, D-06,
D-17, D-18, D-19, D-20 and resolves 19-RESEARCH Open Questions 2 & 3.

Eligibility (D-04): ONLY ``confidence == "confirmed"`` findings are file-eligible.
Everything below confirmed (high/medium/candidate/corroborated) is excluded —
the verification layer (Phase 17) is the gate that earns a finding the right to
become an outward-facing GitHub issue.

Tiering:
  * SOLO (D-05): ``critical`` / ``blocker`` confirmed findings each become their
    own dedicated issue — they are individually serious enough to warrant focus.
  * ROLLUP (D-06): ``major`` / ``minor`` / ``info`` confirmed findings are grouped
    by dimension into one rollup issue per dimension (a checklist) — filing one
    issue per minor finding would be spam.

Body sourcing (D-17, OQ2/OQ3): bodies are SIDECAR-FAITHFUL only. The persisted
ScanReport carries ``schema_version``, ``meta``, ``findings``, ``scope_ledger``
and NOTHING ELSE — the synthesis pass's in-memory priority ranking and its
top-finding selection are NEVER serialized to the sidecar.
So the solo body's "why confirmed" rationale is sourced from
``finding.confidence_caveat`` (the text the Phase 17 verification stage appends
on promotion) plus the ``meta.critic_reviewed`` / ``meta.critic_total_queue``
honest-partial disclosure — NOT from absent priority/verification records (the
OQ2/OQ3 resolution).

Secret-lint gate (D-19/D-20): every assembled draft's title+body runs through
``render.secret_lint.lint_buffer`` (the hard-block chokepoint) BEFORE it can
flow to the filer. A hit blocks THAT ONE draft (its ``secret_lint_blocked`` flag
is set and it is left out of the clean set); the rest survive. The run is NEVER
aborted on a single tainted draft (D-20). This is the phase's primary
secret-exfiltration mitigation (T-19-02), located here at body-build time so
nothing un-linted can ever reach Plan 04's ``gh issue create``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from repo_audit.issues.fingerprint import (
    build_fingerprint,
    build_rollup_fingerprint,
    embed_marker,
)
from repo_audit.render.secret_lint import SecretsDetected, lint_buffer
from repo_audit.schema.enums import Dimension
from repo_audit.schema.finding import Finding
from repo_audit.schema.report import ScanReport
from repo_audit.verification.record import build_finding_ref

# D-05 / D-06 tiering sets.
SOLO: frozenset[str] = frozenset({"critical", "blocker"})
ROLLUP: frozenset[str] = frozenset({"major", "minor", "info"})

# Canonical 7-dimension bucket order (hard-coded from enums.Dimension so a
# defensive bucket exists for every taxonomy member; a finding whose dimension
# falls outside this set is bucketed under "other" rather than crashing).
_DIMENSIONS: tuple[str, ...] = (
    "security",
    "architecture_rot",
    "test_integrity",
    "correctness",
    "quality",
    "process",
    "observability",
)


@dataclass
class IssueDraft:
    """One proposed GitHub issue (solo or per-dimension rollup).

    Mutable on purpose: the filer test (Plan 03) injects a secret into a
    draft's ``body`` after construction to exercise the block-one-file-rest
    path, so ``body`` must be reassignable.
    """

    kind: Literal["solo", "rollup"]
    title: str
    body: str
    labels: list[str]
    fingerprint: str
    dimension: str | None = None
    rule_ids: list[str] = field(default_factory=list)
    member_refs: list[str] = field(default_factory=list)
    secret_lint_blocked: bool = False


def _why_confirmed_line(finding: Finding, report: ScanReport) -> str:
    """The 'why confirmed' rationale — sidecar-faithful (OQ2/OQ3).

    Sourced from finding.confidence_caveat (the verification stage's appended
    text) plus an honest-partial critic-N-of-M disclosure when meta carries it.
    Does NOT read the synthesis-only ranking fields — they are not persisted.
    """
    caveat = (finding.confidence_caveat or "").strip()
    parts = [caveat] if caveat else []
    reviewed = report.meta.critic_reviewed
    total = report.meta.critic_total_queue
    if reviewed is not None and total is not None:
        parts.append(f"Critic reviewed {reviewed} of {total} queued findings.")
    # TODO: synthesis priority rationale is not in the sidecar (OQ2) — re-run
    # compute_priority_score here if a numeric priority is ever wanted.
    return " ".join(parts) if parts else "Promoted to confirmed by verification."


def _solo_body(finding: Finding, report: ScanReport, fp: str) -> str:
    """Assemble a solo issue body from sidecar-faithful fields only (D-17)."""
    ref = build_finding_ref(finding)  # human-readable DISPLAY ref only (D-13)
    snippet = (finding.evidence.output_snippet or "").strip()
    lines = [
        f"**Severity:** {finding.severity}",
        f"**Confidence:** {finding.confidence}",
        f"**Dimension:** {finding.dimension}",
        f"**Location:** `{ref}`",
        f"**Tool / rule:** {finding.source_tool or '—'} / {finding.rule_id or '—'}",
        "",
        "### Recommendation",
        finding.recommendation or "_No recommendation recorded._",
        "",
        "### Why confirmed",
        _why_confirmed_line(finding, report),
    ]
    if snippet:
        lines += ["", "### Evidence", "```", snippet, "```"]
    return embed_marker("\n".join(lines), fp)


def _rollup_body(
    dimension: str,
    members: list[Finding],
    report: ScanReport,
    dim_fp: str,
    member_fps: list[str],
) -> tuple[str, list[str]]:
    """Assemble a rollup checklist body; return (body, member_rule_ids).

    Each checklist line embeds its own per-finding fingerprint marker; the body
    tail carries the SYNTHETIC dimension-level fingerprint (``dim_fp``, CR-01) —
    distinct from any single member's marker, so the tail marker uniquely
    identifies the rollup for dedup. ``member_fps`` is the parallel list of
    per-member fingerprints (same order as ``members``) computed once by the
    caller so the inline per-member markers and the synthetic rollup identity
    are derived from one consistent set.
    """
    lines = [
        f"Confirmed `{dimension}` findings grouped into one rollup "
        "(major/minor/info — D-06).",
        "",
    ]
    rule_ids: list[str] = []
    for f, member_fp in zip(members, member_fps):
        ref = build_finding_ref(f)
        rule_ids.append(f.rule_id)
        rec = (f.recommendation or "").strip() or "(no recommendation)"
        # The hidden per-member marker rides inline so a dedup re-run can match
        # an individual member even inside a rollup.
        marker = "<!-- arch-fingerprint: {} -->".format(member_fp)
        lines.append(f"- [ ] **[{f.severity}]** `{ref}` — {rec} {marker}")
    return embed_marker("\n".join(lines), dim_fp), rule_ids


def _lint_clean(draft: IssueDraft) -> bool:
    """Run the D-19 secret-lint chokepoint over a draft's title+body.

    Returns True when clean. On a hit, sets ``secret_lint_blocked`` and returns
    False — the caller drops this ONE draft and keeps the rest (D-20). Never
    re-raises (block-one-keep-rest, never abort the whole run).
    """
    try:
        lint_buffer(
            f"{draft.title}\n{draft.body}",
            buffer_name=f"issue-draft:{draft.fingerprint}",
        )
    except SecretsDetected:
        draft.secret_lint_blocked = True
        return False
    return True


def build_drafts(
    report: ScanReport,
    *,
    repo_root: Path | None = None,
    owner_repo: str | None = None,
) -> list[IssueDraft]:
    """Build the confirmed-only, tiered, secret-lint-gated issue drafts.

    Eligibility (D-04): only ``confidence == "confirmed"`` findings. Critical/
    blocker → solo drafts (D-05); major/minor/info → one rollup per dimension
    (D-06). Each assembled draft is run through the secret-lint chokepoint
    (D-19); a tainted draft is dropped and the rest survive (D-20).

    Returns the clean drafts (solos first, then rollups in canonical dimension
    order). The owner_repo / repo_root params are accepted for the filer's call
    shape; identity normalization of paths is handled in the fingerprint layer.
    """
    confirmed = [f for f in report.findings if f.confidence == "confirmed"]

    drafts: list[IssueDraft] = []

    # --- Solos (D-05) ----------------------------------------------------- #
    for finding in confirmed:
        if finding.severity not in SOLO:
            continue
        fp = build_fingerprint(finding, repo_root=repo_root)
        body = _solo_body(finding, report, fp)
        # WR-03: guard against a trailing-empty rule_id (it defaults to "") so the
        # title never renders as "[arch][critical] security: " with a dangling
        # colon-space.
        rule = finding.rule_id or "(unlabeled)"
        title = f"[arch][{finding.severity}] {finding.dimension}: {rule}"
        draft = IssueDraft(
            kind="solo",
            title=title,
            body=body,
            labels=["arch-audit", f"severity:{finding.severity}", finding.dimension],
            fingerprint=fp,
            dimension=finding.dimension,
            rule_ids=[finding.rule_id],
            member_refs=[build_finding_ref(finding)],
        )
        drafts.append(draft)

    # --- Rollups (D-06): group major/minor/info by dimension -------------- #
    buckets: dict[str, list[Finding]] = {d: [] for d in _DIMENSIONS}
    buckets["other"] = []  # defensive bucket for a dimension outside the 7
    for finding in confirmed:
        if finding.severity not in ROLLUP:
            continue
        key = finding.dimension if finding.dimension in buckets else "other"
        buckets[key].append(finding)

    for dimension in (*_DIMENSIONS, "other"):
        members = buckets[dimension]
        if not members:
            continue
        # Dimension-level fingerprint (CR-01): a SYNTHETIC identity hashed over
        # ``("rollup", dimension, *sorted(member_fingerprints))`` — distinct from
        # any single member's fingerprint (the "rollup" prefix guarantees no
        # collision) and order-stable, so a whole dimension can never be
        # false-dropped on one member's marker and membership churn is visible to
        # dedup. Member fingerprints are computed once here and threaded into the
        # body so the inline per-member markers match the synthetic identity.
        member_fps = [build_fingerprint(m, repo_root=repo_root) for m in members]
        dim_fp = build_rollup_fingerprint(member_fps, dimension=dimension)
        body, rule_ids = _rollup_body(
            dimension, members, report, dim_fp, member_fps
        )
        title = f"[arch][rollup] {dimension}: {len(members)} confirmed finding(s)"
        draft = IssueDraft(
            kind="rollup",
            title=title,
            body=body,
            labels=["arch-audit", dimension],
            fingerprint=dim_fp,
            dimension=dimension,
            rule_ids=rule_ids,
            member_refs=[build_finding_ref(f) for f in members],
        )
        drafts.append(draft)
    # TODO config knob (D-18 permits optional label config); labels hard-coded.

    # --- D-19/D-20 secret-lint gate: drop tainted drafts, keep the rest --- #
    return [d for d in drafts if _lint_clean(d)]


__all__ = ["IssueDraft", "SOLO", "ROLLUP", "build_drafts"]
