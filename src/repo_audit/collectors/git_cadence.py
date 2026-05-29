"""COLL-01 — git cadence findings (commits, windows, contributors, project age).

When to use: when narrating the `process` dimension — discussing commit
cadence, contributor diversity, project age, or whether the repo shows
signs of healthy day-to-day momentum. Returns one Finding per cadence
metric (commits in last 7/30/60/90 days; distinct coding days;
contributor top-5; project age in days). Data comes from pygit2's
walk over the HEAD commit history.

When NOT to use: for code-quality signals (use get_eslint_lint), file
inventory (use get_loc_inventory_findings), or TODOs in the working
tree (use get_todo_markers_findings). For history-derived churn
statistics not yet covered here, narrate the gap honestly.
"""
# Implementation notes (preserved from the original module docstring):
# Walks Repository.walk(head.target, SortMode.TIME) once and aggregates:
#   commits_total; commits_by_window for 7/30/60/90 days (inclusive
#   boundary); distinct_coding_days (set of ISO date strings);
#   contributor_count + contributors_top5 (by commit count, descending);
#   project_age_days (last_ts - first_ts in days).
# Edge cases (RESEARCH.md §"Pattern 1: pygit2 cadence collector"):
#   not a git repo -> status='unavailable', notes=<exception>;
#   empty HEAD (fresh `git init`) -> status='unavailable',
#   notes='no commits in HEAD'; shallow clone -> walks available history
#   with partial_history flag in parsed_value.
# Pitfall 2: import SortMode from pygit2.enums (the bare module-level sort
#   constant is deprecated in pygit2 1.19+).
# SAFE-01 reminder: severity is 'info' — no confidence_caveat required.
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pygit2
from pygit2.enums import SortMode

from repo_audit.collectors import register_collector
from repo_audit.collectors.base import CollectorResult
from repo_audit.schema.finding import Evidence, Finding


_WINDOWS_DAYS: tuple[int, ...] = (7, 30, 60, 90)
_TOP_N_CONTRIBUTORS: int = 5


@register_collector
def run(repo_path: Path, repo_index: dict) -> CollectorResult:
    # Open repo
    try:
        repo = pygit2.Repository(str(repo_path))
    except pygit2.GitError as exc:
        return CollectorResult(
            status="unavailable",
            notes=f"not a git repo: {exc}",
            source_collector="git_cadence",
            dimension="process",
            scanned_paths=[str(repo_path)],
        )

    # Resolve HEAD target (raises on empty HEAD)
    try:
        head_target = repo.head.target
    except (pygit2.GitError, KeyError) as exc:
        return CollectorResult(
            status="unavailable",
            notes=f"no commits in HEAD: {type(exc).__name__}",
            source_collector="git_cadence",
            dimension="process",
            scanned_paths=[str(repo_path)],
        )

    # Walk + aggregate
    now = datetime.now(timezone.utc)
    thresholds: dict[str, datetime] = {
        f"{d}d": now - timedelta(days=d) for d in _WINDOWS_DAYS
    }
    counts: dict[str, int] = {f"{d}d": 0 for d in _WINDOWS_DAYS}
    coding_days: set[str] = set()
    authors: Counter[str] = Counter()
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    partial_history = False

    try:
        for commit in repo.walk(head_target, SortMode.TIME):
            ts = datetime.fromtimestamp(commit.commit_time, timezone.utc)
            if last_ts is None:
                last_ts = ts  # newest first under SortMode.TIME
            first_ts = ts     # oldest at end of iteration
            coding_days.add(ts.date().isoformat())
            authors[commit.author.email] += 1
            for label, threshold in thresholds.items():
                if ts >= threshold:
                    counts[label] += 1
    except pygit2.GitError:
        # Shallow clone or corrupt history mid-walk: report what we have.
        partial_history = True

    commits_total = sum(authors.values())
    if commits_total == 0:
        # No iterations produced — degenerate; treat as unavailable.
        return CollectorResult(
            status="unavailable",
            notes="walk yielded 0 commits",
            source_collector="git_cadence",
            dimension="process",
            scanned_paths=[str(repo_path)],
        )

    project_age_days = (
        (last_ts - first_ts).days if (first_ts and last_ts) else 0
    )
    contributors_top5 = [
        [email, count] for email, count in authors.most_common(_TOP_N_CONTRIBUTORS)
    ]

    parsed_value = {
        "commits_total": commits_total,
        "commits_by_window": counts,
        "distinct_coding_days": len(coding_days),
        "contributor_count": len(authors),
        "contributors_top5": contributors_top5,
        "project_age_days": project_age_days,
        "partial_history": partial_history,
    }

    finding = Finding(
        dimension="process",
        severity="info",
        evidence_type="static",
        confidence="high",
        source_tool="pygit2",
        source_collector="git_cadence",
        evidence=Evidence(
            tool="pygit2",
            parsed_value=parsed_value,
        ),
        recommendation="",
    )

    return CollectorResult(
        findings=[finding],
        status="ok",
        source_collector="git_cadence",
        dimension="process",
        scanned_paths=[str(repo_path)],
        notes="partial git history (mid-walk error)" if partial_history else "",
    )
