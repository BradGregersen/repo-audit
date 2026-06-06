"""Issue filing — the gated outward action (Phase 19).

This package turns a freshly-scanned ScanReport sidecar into confirmed-only
GitHub issues, gated strictly behind an explicit propose-then-approve y/N gate
(D-11/D-12). It is the ONLY part of the tool that writes outside the target
repo's ``docs/state-reports/`` — and even that write happens only after the user
says ``y`` (or ``--yes`` is passed for CI).

:func:`run_issues` is the single-source-of-truth orchestrator the thin
``repo-audit issues`` CLI command delegates to, mirroring
``orchestration.scan_runner.run_scan``: it threads
load → resolve/guard → draft → dedup → propose → file → report and never raises
across its boundary, folding every failure into an
:class:`~repo_audit.issues.result.IssuesResult` (``rc`` + ``notes``).

Pipeline (RESEARCH System Architecture Diagram steps [1]-[8]):
  [1] resolve/guard the file target from the repo's git origin (D-09/D-10) —
      the wrong-repo guard runs BEFORE any draft so an accidental cross-repo
      file is blocked at the door.
  [2] load the most-recent (today-inclusive) sidecar (D-01/D-02); no sidecar →
      a clear rc=5 error; a stale sidecar warns but proceeds (D-03).
  [3] build the confirmed-only, tiered, secret-lint-gated drafts (D-04..D-06,
      D-19/D-20); drafts blocked at build time are recorded.
  [4] dedup against OPEN issues' fingerprint markers (D-14/D-16) — matches move
      to ``skipped_duplicate``; survivors continue.
  [5] nothing to file → rc=0 success.
  [6] PROPOSE: the CLI prints the dry-run; the gate (``confirm`` / ``--yes``)
      decides. Declining files NOTHING (D-12) — rc=0, ``filed=[]``.
  [7] FILE: the one outward write — ensure the umbrella label once, then file
      each survivor (block-one-keep-rest on a late secret-lint hit).
  [8] return the IssuesResult the CLI renders via :meth:`IssuesResult.summary`.
"""
from __future__ import annotations

import warnings
from collections.abc import Callable
from pathlib import Path

from repo_audit.issues.dedup import find_duplicate, list_open_issue_bodies
from repo_audit.issues.draft import IssueDraft, build_drafts
from repo_audit.issues.filer import file_all
from repo_audit.issues.loader import NoSidecarError, load_latest_sidecar
from repo_audit.issues.result import IssuesResult
from repo_audit.issues.targeting import (
    IdentityGuardError,
    assert_target_matches,
)

# Exit codes (mirrored in the CLI docstring).
_RC_OK = 0
_RC_TARGET = 4  # gh unavailable / unauthenticated / wrong-repo guard
_RC_NO_SIDECAR = 5  # no usable sidecar (run `repo-audit scan` first, D-02)


def run_issues(
    repo_path: Path,
    *,
    assume_yes: bool = False,
    confirm: Callable[[], bool] | None = None,
    on_propose: Callable[[list[IssueDraft], list[tuple[str, str]]], None] | None = None,
) -> IssuesResult:
    """Run the full ``repo-audit issues`` pipeline; never raise across the boundary.

    Threads the RESEARCH pipeline in order, folding every failure into an
    :class:`IssuesResult` (``rc`` + ``notes``) — the same never-raise contract as
    ``run_scan``. The one outward write (``gh issue create``) happens ONLY in the
    file step, strictly after the gate (``assume_yes`` True or ``confirm()``
    returns True). Declining (or no approver) files NOTHING (D-12).

    Args:
        repo_path: the scanned repo dir (carries the sidecar + the git origin).
        assume_yes: skip the y/N gate and file (CI / ``--yes``). Default False.
        confirm: a zero-arg callable returning the gate verdict (the CLI passes a
            ``typer.confirm`` thunk). When ``assume_yes`` is False and ``confirm``
            is None or returns False, nothing is filed.
        on_propose: an optional hook invoked with ``(survivors, skipped_duplicate)``
            at the propose step (step [6]), BEFORE the gate — the CLI uses it to
            print the dry-run so the user sees exactly what a ``y`` would file.
            Keeps the CLI thin (it only prints) while ``run_issues`` owns the
            pipeline that computes the survivor set.

    Returns:
        An :class:`IssuesResult` with rc + filed / skipped_duplicate /
        blocked_by_secret_lint + notes.
    """
    repo_path = Path(repo_path)

    # [2] load the sidecar first so we know the SCANNED slug for the guard.
    #     (No-sidecar is the most common, clearest error — surface it before any
    #     gh/git probe so the user gets the actionable "run repo-audit scan" message.)
    #     D-03 staleness: the loader WARNS (does not raise) on a stale sidecar;
    #     capture that warning into the result notes so the CLI surfaces it on
    #     stderr regardless of the process-wide warning filter, while still
    #     PROCEEDING (a stale finding set is still actionable).
    notes: list[str] = []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            report = load_latest_sidecar(repo_path)
        except NoSidecarError as exc:
            return IssuesResult(rc=_RC_NO_SIDECAR, notes=[str(exc)])
    for w in caught:
        notes.append(str(w.message))

    # [1] resolve/guard the file target from the git origin BEFORE any draft.
    #     assert_target_matches uses ONLY the origin remote (no gh required) so
    #     the guard works offline; the gh nameWithOwner cross-check is the second
    #     online layer (resolve_target) the CLI may surface separately.
    try:
        owner_repo = assert_target_matches(
            repo_path, scanned_slug=report.meta.repo_slug
        )
    except IdentityGuardError as exc:
        return IssuesResult(rc=_RC_TARGET, notes=[*notes, str(exc)])

    # [3] build the confirmed-only, tiered, secret-lint-gated drafts.
    drafts = build_drafts(report, repo_root=repo_path, owner_repo=owner_repo)

    # [4] dedup against OPEN issues' fingerprint markers (D-14/D-16). Degrades to
    #     an empty open set on any gh failure (never raises) → no false skips.
    open_issues = list_open_issue_bodies(owner_repo, repo_path)
    survivors: list[IssueDraft] = []
    skipped_duplicate: list[tuple[str, str]] = []
    for draft in drafts:
        existing_url = find_duplicate(draft.fingerprint, open_issues)
        if existing_url is not None:
            skipped_duplicate.append((draft.ref, existing_url))
        else:
            survivors.append(draft)

    # [5] nothing to file is success.
    if not survivors:
        return IssuesResult(
            rc=_RC_OK,
            filed=[],
            skipped_duplicate=skipped_duplicate,
            notes=[*notes, "Nothing to file."],
        )

    # [6] PROPOSE → the all-or-nothing gate (D-11/D-12). Surface the dry-run via
    #     the CLI's on_propose hook BEFORE the gate, then honor the verdict.
    if on_propose is not None:
        on_propose(survivors, skipped_duplicate)
    approved = assume_yes or (confirm is not None and bool(confirm()))
    if not approved:
        return IssuesResult(
            rc=_RC_OK,
            filed=[],
            skipped_duplicate=skipped_duplicate,
            notes=[*notes, "Aborted — nothing filed (D-12)."],
        )

    # [7] FILE — the one outward write, strictly after approval.
    outcome = file_all(repo_path, survivors, owner_repo=owner_repo)

    # [8] assemble the result. Per-issue create failures fold into notes; a
    #     late secret-lint block folds into blocked_by_secret_lint.
    return IssuesResult(
        rc=_RC_OK,
        filed=outcome.filed_urls,
        skipped_duplicate=skipped_duplicate,
        blocked_by_secret_lint=outcome.blocked_refs,
        notes=[*notes, *outcome.errors],
    )


__all__ = ["run_issues", "IssuesResult"]
