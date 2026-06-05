"""Tiered corroboration — the SOLE deterministic path that promotes
``candidate → corroborated`` (RAISES ONLY, never deletes, never touches severity).

This module owns the full corroboration ladder for Phase 17. It is the
generalization of ``adapters/sca/corroborate.py`` (tier-1 identity, two-source
agreement) and the new home of ``render/corroboration.py::is_corroborated``
(tier-3 coarse), factored here so the render-time and pre-narration checks can
never drift (CONTEXT D-17 discretion; RESEARCH §"Don't Hand-Roll").

TIER LADDER (strongest wins, the winning tier is recorded in a VerificationRecord):

    tier-1 identity  — same normalized rule_id seen by ≥2 DISTINCT source_tools.
    tier-2 locus     — same file + line within ±line_window + same dimension,
                       ≥2 distinct tools.
    tier-3 coarse    — is_corroborated: same dimension + same file, source_tool
                       diversity ≥2 (no id/line match).
    reachability     — a single-tool candidate whose check_reachable(...) == True
                       (D-17-02 independent 2nd signal).
    runtime          — evidence_type == 'runtime' auto-corroborates (D-17-07).

HARD CONTRACTS:
    * RAISES ONLY — ``len(output) == len(input)``; no finding is ever removed
      (D-17-04). The bump touches CONFIDENCE only; SEVERITY is left exactly as
      the parser capped it (DI-06-01-01 — the ``confirmed`` gate in stage.py is
      the sole path that finally permits critical/blocker severity).
    * CAVEAT PRESERVATION (Pitfall 3) — promotion is via ``model_copy`` which
      re-runs ``_enforce_critical_static_caveat``; a static-critical finding's
      ``confidence_caveat`` is preserved+appended, never dropped.
    * DETERMINISTIC (SC-5) — output ordering + tier assignments are independent
      of input ordering (shuffled input → identical output).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from repo_audit.verification.reachability import check_reachable
from repo_audit.verification.record import (
    VerificationRecord,
    build_finding_ref,
)

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding

_CORROBORATION_CAVEAT = (
    "Promoted to corroborated by the Phase 17 verification layer "
    "(tiered multi-signal agreement)."
)

# Strength ordering for "strongest tier wins" (lower index = stronger). The two
# signals sit below the three structural tiers; runtime always corroborates.
_TIER_STRENGTH: dict[str, int] = {
    "identity": 0,
    "locus": 1,
    "coarse": 2,
    "reachability": 3,
    "runtime": 4,
    "none": 99,
}


def is_corroborated(finding: "Finding", all_findings: "list[Finding]") -> bool:
    """Tier-3 coarse — source_tool diversity ≥ 2 across same-dimension + same-file.

    MOVED here verbatim from ``render/corroboration.py`` (D-69) so the render-time
    and pre-narration checks are the SAME function and cannot drift.
    """
    same_dim_same_file = [
        f
        for f in all_findings
        if f is not finding
        and getattr(f, "dimension", None) == getattr(finding, "dimension", None)
        and getattr(f, "file", None) == getattr(finding, "file", None)
    ]
    source_tools = {getattr(f, "source_tool", "") for f in same_dim_same_file} | {
        getattr(finding, "source_tool", "")
    }
    return len({t for t in source_tools if t}) >= 2


def _bump_to_corroborated(finding: "Finding") -> "Finding":
    """Return a copy of ``finding`` at ``corroborated`` with the agreement caveat.

    Confidence ONLY — severity untouched (Phase 17's confirmed gate owns severity
    promotion). The existing caveat is preserved and the corroboration note is
    appended so neither the SAFE-01 rationale nor the corroboration rationale is
    lost (Pitfall 3 — the validators re-run on model_copy).
    """
    existing = (finding.confidence_caveat or "").strip()
    if existing and _CORROBORATION_CAVEAT not in existing:
        caveat = f"{existing} {_CORROBORATION_CAVEAT}"
    elif existing:
        caveat = existing
    else:
        caveat = _CORROBORATION_CAVEAT
    return finding.model_copy(
        update={"confidence": "corroborated", "confidence_caveat": caveat}
    )


def _norm_id(finding: "Finding") -> str:
    """Normalized identity key (rule_id, uppercased) — empty if none."""
    rid = (getattr(finding, "rule_id", "") or "").strip().upper()
    return rid


def _distinct_tools(findings: "list[Finding]") -> set[str]:
    return {(getattr(f, "source_tool", "") or "") for f in findings if getattr(f, "source_tool", "")}


def _winning_tier(
    finding: "Finding",
    all_findings: "list[Finding]",
    *,
    reachability_fn: Callable | None,
    repo_path,
    line_window: int,
) -> tuple[str, list[str]]:
    """Return ``(tier, corroborated_by)`` for ``finding`` — strongest applicable.

    ``corroborated_by`` is the sorted set of distinct source_tools backing the
    promotion (including the finding's own tool). ``tier == "none"`` means no
    signal applied (stays candidate).
    """
    # runtime auto-corroborate (D-17-07) — always wins as a standalone signal.
    if getattr(finding, "evidence_type", None) == "runtime":
        return "runtime", sorted(
            {getattr(finding, "source_tool", "") or ""} - {""}
        )

    own_tool = getattr(finding, "source_tool", "") or ""

    # tier-1 identity: same normalized rule_id, ≥2 distinct tools.
    nid = _norm_id(finding)
    if nid:
        id_peers = [
            f for f in all_findings if f is not finding and _norm_id(f) == nid
        ]
        tools = _distinct_tools([finding, *id_peers])
        if len(tools) >= 2:
            return "identity", sorted(tools)

    # tier-2 locus: same file + line±window + same dimension, ≥2 distinct tools.
    f_file = getattr(finding, "file", None)
    f_line = getattr(finding, "line", None)
    f_dim = getattr(finding, "dimension", None)
    if f_file is not None and f_line is not None:
        locus_peers = [
            f
            for f in all_findings
            if f is not finding
            and getattr(f, "file", None) == f_file
            and getattr(f, "dimension", None) == f_dim
            and getattr(f, "line", None) is not None
            and abs(getattr(f, "line") - f_line) <= line_window
        ]
        tools = _distinct_tools([finding, *locus_peers])
        if len(tools) >= 2:
            return "locus", sorted(tools)

    # tier-3 coarse: same dim+file, tool diversity ≥2.
    if is_corroborated(finding, all_findings):
        coarse_peers = [
            f
            for f in all_findings
            if getattr(f, "dimension", None) == f_dim
            and getattr(f, "file", None) == f_file
        ]
        return "coarse", sorted(_distinct_tools(coarse_peers))

    # reachability signal (D-17-02): single-tool candidate + reachable==True.
    if reachability_fn is not None:
        try:
            reachable = reachability_fn(finding, repo_path)
        except Exception:
            reachable = None
        if reachable is True:
            return "reachability", sorted({own_tool} - {""})

    return "none", sorted({own_tool} - {""})


def tiered_corroborate(
    findings: "list[Finding]",
    *,
    reachability_fn: Callable | None = check_reachable,
    repo_path=None,
    line_window: int = 3,
) -> "tuple[list[Finding], list[VerificationRecord]]":
    """Promote ``candidate → corroborated`` across the tier ladder (RAISES ONLY).

    Args:
        findings: the merged finding set.
        reachability_fn: the tri-state reachability signal (D-17-02). Defaults to
            ``check_reachable``; pass ``None`` to disable the reachability tier
            (e.g. when no ``repo_path`` is available).
        repo_path: repo root for the reachability check (None disables it).
        line_window: locus-tier line tolerance (A2 default 3, config-tunable).

    Returns:
        ``(out_findings, records)`` where ``len(out_findings) == len(findings)``
        (count-conserving, deterministically ordered by finding_ref) and
        ``records`` is one ``VerificationRecord`` per finding carrying the winning
        tier + corroborated_by. Findings whose ``corroboration_tier == "none"``
        are returned unchanged (still candidate).
    """
    if not findings:
        return [], []

    # Determine the winning tier per finding against the FULL set (so the result
    # is independent of input ordering — determinism, SC-5).
    out: list[Finding] = []
    records: list[VerificationRecord] = []
    for idx, f in enumerate(findings):
        tier, corroborated_by = _winning_tier(
            f,
            findings,
            reachability_fn=reachability_fn,
            repo_path=repo_path,
            line_window=line_window,
        )
        if tier != "none":
            promoted = _bump_to_corroborated(f)
        else:
            promoted = f
        out.append(promoted)
        records.append(
            VerificationRecord(
                finding_ref=build_finding_ref(f),
                # 17-04: stamp the per-finding identity token = the zero-based
                # INPUT-list index. This is stamped BEFORE the (finding,record)
                # re-sort below, so the record carries identity even though the
                # finding's list position no longer survives the sort.
                candidate_token=idx,
                corroboration_tier=tier,  # type: ignore[arg-type]
                corroborated_by=corroborated_by,
                final_confidence=promoted.confidence,
            )
        )

    # Deterministic output order (SC-5): sort the (finding, record) pairs by the
    # canonical fingerprint. Count is conserved — nothing is dropped.
    paired = sorted(
        zip(out, records, strict=True),
        key=lambda pair: (
            pair[1].finding_ref,
            _TIER_STRENGTH.get(pair[1].corroboration_tier, 99),
        ),
    )
    out_sorted = [p[0] for p in paired]
    records_sorted = [p[1] for p in paired]
    return out_sorted, records_sorted


__all__ = ["tiered_corroborate", "is_corroborated"]
