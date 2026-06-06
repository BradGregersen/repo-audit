"""``run_synthesis`` — the never-raise prioritization stage (SYN-01/02, D-25).

Clones the ``run_verification`` never-raise tuple contract (verification/stage.py):
it stamps ``candidate_token`` over the INPUT findings BEFORE any re-sort (the token
is the zero-based input index — the SAME identity the verification records carry),
reads ``read_synthesis_config(repo_path)``, builds the bundled offline ``KEV_SET``,
looks up per-finding KEV + (opt-in) EPSS, then scores → ranks → selects the Top-N.

Every sub-stage is wrapped so a failure leaves findings UNRANKED-BUT-PRESENT and
the scan still completes (D-25 / V7): on any error the stage returns the input
findings, an empty score map, an empty Top-N, and a ``synthesis_meta`` recording
the degrade. NOTHING raises out of this function.

Returns a 4-tuple ``(findings, scores_by_token, top_findings_data, synthesis_meta)``
where ``top_findings_data`` is the ordered ``(token, finding, PriorityScore | None)``
list the renderer/agent boundary (Plan 18-03) folds into ``TopFinding`` — this stage
does NOT build that boundary model (Plan 18-03 owns it).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from repo_audit.synthesis.config import read_synthesis_config
from repo_audit.synthesis.kev import finding_cve, is_kev, load_kev_set
from repo_audit.synthesis.rank import rank_findings
from repo_audit.synthesis.score import score_findings
from repo_audit.synthesis.select import select_top_n

if TYPE_CHECKING:
    from repo_audit.schema.finding import Finding
    from repo_audit.synthesis.record import PriorityScore
    from repo_audit.verification.record import VerificationRecord


def run_synthesis(
    findings: "list[Finding]",
    records: "list[VerificationRecord]",
    *,
    repo_path: Any = None,
    epss_enabled: bool = False,
) -> "tuple[list[Finding], dict[int, PriorityScore], list[tuple[int, Finding, PriorityScore | None]], dict]":
    """Score, rank, and select the Top-N under a never-raise contract (D-25).

    Args:
        findings: the active (post-verification) finding set.
        records: the parallel :class:`VerificationRecord` list; each carries a
            ``candidate_token`` (the zero-based input index dispatch identity).
        repo_path: repo root for ``read_synthesis_config`` (None → defaults).
        epss_enabled: the opt-in EPSS egress gate (default OFF → EPSS neutral).
            The CLI ``--epss`` flag threads through here; a config
            ``epss_enabled: true`` is honored too.

    Returns:
        ``(findings, scores_by_token, top_findings_data, synthesis_meta)``.
        ``synthesis_meta`` carries ``top_n``, ``kev_count``, ``epss_enabled``,
        ``selected`` (Top-N length), and ``degraded`` (True iff a sub-stage failed
        and findings are unranked-but-present).

    NEVER raises: any sub-stage failure leaves findings unranked-but-present and
    still returns the full 4-tuple with ``degraded=True``.
    """
    findings = list(findings)
    meta: dict[str, Any] = {
        "top_n": 0,
        "kev_count": 0,
        "epss_enabled": bool(epss_enabled),
        "selected": 0,
        "degraded": False,
    }

    # --- config (never-raise reader; defaults on any failure). -----------------
    try:
        config = read_synthesis_config(repo_path)
    except Exception:  # noqa: BLE001 — D-25
        from repo_audit.synthesis.config import SynthesisConfig

        config = SynthesisConfig()
    # The flag OR a per-repo config opt-in enables EPSS; default stays OFF.
    epss_on = bool(epss_enabled) or bool(getattr(config, "epss_enabled", False))
    meta["top_n"] = config.top_n
    meta["epss_enabled"] = epss_on

    # --- stamp candidate_token over the INPUT findings (mirror run_verification:
    # the pairing identity is the zero-based input index, stamped BEFORE re-sort). -
    try:
        tokened: list[tuple[int, "Finding"]] = list(enumerate(findings))
        records_by_token: dict[int, "VerificationRecord"] = {
            getattr(r, "candidate_token", -1): r for r in (records or [])
        }
    except Exception:  # noqa: BLE001 — D-25: degrade to unranked-but-present
        meta["degraded"] = True
        return findings, {}, [], meta

    # --- KEV band (bundled offline snapshot) + opt-in EPSS per finding. ---------
    try:
        kev_set = load_kev_set()
        kev_tokens = frozenset(
            token for token, f in tokened if is_kev(f, kev_set)
        )
        meta["kev_count"] = len(kev_tokens)
    except Exception:  # noqa: BLE001 — KEV unavailable → every finding band 0
        kev_tokens = frozenset()

    epss_by_token: dict[int, float] = {}
    if epss_on:
        try:
            from repo_audit.synthesis.epss import epss_lookup

            timeout = getattr(config, "epss_timeout_seconds", 15)
            for token, f in tokened:
                cve = finding_cve(f)
                if cve is None:
                    continue
                score = epss_lookup(cve, enabled=True, timeout_seconds=timeout)
                if score is not None:
                    epss_by_token[token] = score
        except Exception:  # noqa: BLE001 — EPSS neutral on any failure (D-18-02)
            epss_by_token = {}

    # --- score → rank → select (each wrapped; failure degrades, never raises). --
    try:
        scores_by_token = score_findings(
            findings,
            records_by_token,
            kev_tokens=kev_tokens,
            epss_by_token=epss_by_token,
        )
    except Exception:  # noqa: BLE001 — D-25
        meta["degraded"] = True
        return findings, {}, [], meta

    try:
        ranked = rank_findings(tokened, scores_by_token)
    except Exception:  # noqa: BLE001 — D-25: keep scores, skip ranking/selection
        meta["degraded"] = True
        return findings, scores_by_token, [], meta

    try:
        top_findings_data = select_top_n(ranked, scores_by_token, config.top_n)
        meta["selected"] = len(top_findings_data)
    except Exception:  # noqa: BLE001 — D-25
        meta["degraded"] = True
        return findings, scores_by_token, [], meta

    return findings, scores_by_token, top_findings_data, meta


__all__ = ["run_synthesis"]
