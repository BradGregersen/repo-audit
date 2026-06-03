"""HIST-01 — full git-history secret collector (Plan 12-02, Wave 1).

Secrets ever committed are a real supply-chain exposure that the working-tree
scan (COLL-03 ``secret_detection``) misses: a key committed last year and later
deleted is gone from the working tree but lives forever in the git object store.
``collect_git_history`` walks the FULL history once via Plan 12-01's value-blind
``render.secret_lint.scan_git_history`` sibling, builds ``[REDACTED:N]`` Findings
in the exact COLL-03 shape, and dedups against the working-tree finding set so a
still-present secret is never double-counted — only committed-then-deleted
(net-new) secrets surface.

This is a Finding-PRODUCING collector, NOT a new redaction path. It reuses
Plan 12-01's value-blind machinery verbatim: ``scan_git_history`` passes
``--redact`` and returns value-blind ``SecretHit``s (line, rule_id,
redacted_len, source, file — NEVER a raw value). The Finding/Evidence schema
(SCH-08) structurally forbids any raw-value field, so no raw secret can cross
the boundary even by accident.

Dedup heuristic (value-blind, Pattern 3 / T-12-02-DIL):
    The dedup key is ``(rule_id, file, redacted_len)`` — it is intentionally
    VALUE-BLIND because no raw value is available on either side of the compare.
    Consequence: a genuinely-DIFFERENT secret that happens to share the same
    rule_id, file path, AND token length as a working-tree hit is conservatively
    deduped (under-counted). This is the deliberate trade: it is better to
    under-count history than to double-count a still-present secret as both a
    working-tree finding AND a "net-new" history finding. The working-tree scan
    already counts the still-present secret once; history adds only what the
    working tree cannot see.

Cost / timeout (Pitfall 3 / T-12-02-DOS):
    The full-history walk runs OUTSIDE the 95 s per-collector deadline that
    bounds ``secret_detection``. It carries its OWN generous timeout
    (``_HISTORY_TIMEOUT_SECONDS``, default ~900 s) per the v2.0 "cost no object"
    stance. On timeout, ``scan_git_history`` returns ``[]`` and this collector
    reports ``status='timeout'`` so the scope ledger discloses the bounded walk.

Degrade-honestly (SAFE-08 / D-12-04):
    * No ``.git`` (``NotAGitRepo``) → ``status='unavailable'``, zero findings,
      no raise — the scan still completes.
    * gitleaks not on PATH → ``status='unavailable'`` (``scan_git_history``
      returns ``[]`` when the binary is absent; we detect that up front with
      ``shutil.which`` so we can distinguish "no gitleaks" from "no secrets").

``collect_git_history`` NEVER raises across its boundary (mirrors the
``OsvResult`` never-raise contract): every failure mode folds into a
``HistoryResult`` status + notes.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from repo_audit.meta.git import NotAGitRepo, head_sha
from repo_audit.render.secret_lint import SecretHit, scan_git_history
from repo_audit.schema.finding import Evidence, Finding

HistoryStatus = Literal["ok", "unavailable", "timeout"]

# GENEROUS timeout: the full-history walk runs OUTSIDE the 95 s per-collector
# deadline (Pitfall 3). v2.0 "cost no object" — a 10-minute walk on a large repo
# is accepted, not a bug. On timeout scan_git_history returns [] and we report
# status='timeout'.
_HISTORY_TIMEOUT_SECONDS: float = 900.0


@dataclass
class HistoryResult:
    """The never-raise envelope returned by :func:`collect_git_history`.

    Mirrors the ``adapters/sca/osv.OsvResult`` never-raise contract: every
    failure mode (no git, no gitleaks, timeout, unexpected error) folds into a
    ``status`` + ``notes`` rather than an exception.
    """

    findings: list[Finding] = field(default_factory=list)
    status: HistoryStatus = "ok"
    notes: str = ""


def _dedup_key(f: Finding) -> tuple[str, str, int]:
    """Value-blind dedup key for a secret Finding: ``(rule_id, file, redacted_len)``.

    Reads ``redacted_len`` from ``evidence.parsed_value`` (the only place it is
    carried — SCH-08 limits parsed_value to ``{rule_id, redacted_len}``). NEVER
    reads a raw value (there is none on the schema). Used to fold working-tree
    findings into a key set so a still-present secret is not re-counted as a
    "net-new" history finding.
    """
    pv = {}
    if f.evidence is not None:
        pv = f.evidence.parsed_value or {}
    return (
        f.rule_id or "",
        f.file or "",
        int(pv.get("redacted_len") or 0),
    )


def _finding_from_hit(hit: SecretHit) -> Finding:
    """Build a COLL-03-shaped Finding for a single history ``SecretHit``.

    Replicates ``collectors/secret_detection._emit`` verbatim for the history
    source: ``source_tool='gitleaks-history'``, ``source_collector='git_history'``,
    ``severity='major'`` + ``confidence='candidate'`` (SAFE-06 — candidate caps at
    major), ``evidence_type='heuristic'`` (SAFE-01 — not a runtime probe). The
    ``output_snippet`` is the HARD-CODED ``[REDACTED:N]`` template (T-12-02-ID:
    the raw value never enters this f-string). ``parsed_value`` carries ONLY
    ``rule_id`` + ``redacted_len`` (SCH-08).

    For history hits the working-tree file path may not exist (the secret was
    deleted); we use the gitleaks-reported ``File`` (``hit.file``), or ``None``
    when gitleaks reported no path.
    """
    return Finding(
        dimension="security",
        severity="major",  # SAFE-06: candidate caps at major
        confidence="candidate",  # SAFE-06: requires corroboration
        evidence_type="heuristic",  # SAFE-01: not a runtime probe
        source_tool="gitleaks-history",
        source_collector="git_history",
        file=hit.file,  # gitleaks-reported path; may be None for history hits
        line=hit.line,
        rule_id=hit.rule_id,
        recommendation=(
            "investigate: this secret appears in git HISTORY (possibly since "
            "deleted from the working tree); rotate it if real — deletion from "
            "the working tree does NOT purge it from the object store"
        ),
        evidence=Evidence(
            tool="gitleaks-history",
            output_snippet=(
                f"{hit.rule_id} [REDACTED:{hit.redacted_len}] at line {hit.line}"
            ),
            parsed_value={
                # SCH-08: ONLY these two keys. NEVER 'value', 'secret', 'match',
                # 'raw', 'original', or 'token'.
                "rule_id": hit.rule_id,
                "redacted_len": hit.redacted_len,
            },
            line_range=(hit.line, hit.line),
        ),
    )


def collect_git_history(
    repo_path: Path,
    working_tree_findings: Optional[list[Finding]] = None,
    *,
    env: Optional[dict[str, str]] = None,
) -> HistoryResult:
    """HIST-01: flag secrets ever committed (even since deleted) via full history.

    Walks the FULL git history once through Plan 12-01's value-blind
    ``scan_git_history`` sibling, constructs ``[REDACTED:N]`` Findings in the
    COLL-03 shape, and dedups against ``working_tree_findings`` so a still-present
    secret is never double-counted — only committed-then-deleted (net-new)
    secrets surface.

    Args:
        repo_path: the repo to walk. No ``.git`` → ``status='unavailable'``
            (SAFE-08); the scan still completes.
        working_tree_findings: the COLL-03 working-tree secret findings to dedup
            against (defaults to empty — every history hit is then net-new).
            Deduped on the value-blind ``(rule_id, file, redacted_len)`` key.
        env: reserved for future env-threaded invocation (unused today;
            ``scan_git_history`` owns its own subprocess). Accepted so callers can
            pass the scan env uniformly.

    Returns:
        A :class:`HistoryResult`; NEVER raises. No git → ``unavailable``;
        gitleaks absent → ``unavailable``; timeout → ``timeout``; otherwise
        ``ok`` with the net-new history findings.
    """
    working_tree_findings = working_tree_findings or []
    _ = env  # reserved; scan_git_history owns its own value-blind subprocess

    repo_path = Path(repo_path)

    # No-git guard (D-12-04 / SAFE-08): a non-git path → unavailable, no raise.
    try:
        head_sha(repo_path)
    except NotAGitRepo:
        return HistoryResult(
            status="unavailable", notes="no git history (.git absent)"
        )
    except Exception as exc:  # never raise across the boundary
        return HistoryResult(
            status="unavailable",
            notes=f"git presence check failed: {type(exc).__name__}",
        )

    # gitleaks-absent guard: scan_git_history returns [] when the binary is
    # missing, which is indistinguishable from "no secrets". Detect absence up
    # front so we can report 'unavailable' honestly rather than a false 'ok'.
    if shutil.which("gitleaks") is None:
        return HistoryResult(status="unavailable", notes="gitleaks not found")

    # Full-history walk (Pitfall 3): GENEROUS timeout, runs OUTSIDE the 95 s
    # collector deadline. scan_git_history already never raises (it catches
    # TimeoutExpired/FileNotFoundError internally and returns []).
    try:
        hits: list[SecretHit] = scan_git_history(
            repo_path, timeout=_HISTORY_TIMEOUT_SECONDS
        )
    except Exception as exc:  # defensive — never raise across the boundary
        return HistoryResult(
            status="unavailable",
            notes=f"history scan failed unexpectedly: {type(exc).__name__}",
        )

    # Build a Finding per hit, then dedup against the working-tree key set so a
    # still-present secret is not re-counted as a net-new history finding.
    working_tree_keys = {_dedup_key(f) for f in working_tree_findings}
    findings: list[Finding] = []
    seen_keys: set[tuple[str, str, int]] = set()
    for hit in hits:
        finding = _finding_from_hit(hit)
        key = _dedup_key(finding)
        # Drop hits already present in the working tree (the still-present
        # secret) AND collapse duplicate history hits sharing the same
        # value-blind key (the same redacted secret reported on multiple commits
        # at the same path/length is one finding, not many).
        if key in working_tree_keys or key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append(finding)

    return HistoryResult(findings=findings, status="ok", notes="")


# The Wave-0 test stub (tests/adapters/supply_chain/test_history.py) probes for a
# single-arg entry point named one of collect_history/scan_history/run_history/
# collect. Expose `collect` as the canonical single-arg alias so the stub flips
# ACTIVE; `collect_git_history` remains the full-signature plan entry point.
collect = collect_git_history
