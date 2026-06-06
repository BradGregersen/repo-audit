"""Open-issue dedup lookup: list OPEN issues, recover their fingerprint markers.

The second outward-read subprocess seam of ``repo-audit issues`` (``targeting`` is the
other). It owns D-14/D-16 + Pitfall 3:

  * **D-16 skip-on-match** — a draft whose hidden fingerprint marker already
    appears in an OPEN issue is skipped, never re-filed and never edited/commented.
  * **D-14 client-side marker grep** — the fingerprint marker is an HTML comment
    invisible to GitHub's search index, so the only reliable dedup path is to pull
    every open issue's ``body`` and substring-recover the markers locally (reusing
    :func:`issues.fingerprint.extract_fingerprints`).
  * **Pitfall 3 — the silent ``--limit 30`` truncation trap.** ``gh issue list``
    defaults to 30 results; on a busy repo that would silently hide older open
    issues and re-file their findings. We pass an explicit high ``--limit`` so
    dedup sees the full open set.

Every ``gh`` call routes through :func:`run_tool` (shell=False, ``list[str]``
argv, full ``dict(os.environ)`` so gh stays authenticated — Pitfall 4) with an
explicit ``timeout_seconds`` (T-19-07). The function degrades to an empty result
on ANY failure (gh missing, unauthenticated, timeout, malformed JSON) and NEVER
raises — worst case a finding is re-filed and caught by the marker on the next
run, which is strictly safer than crashing the whole ``issues`` command. The
caller (Plan 04) already surfaced auth state via the targeting guard.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.issues.fingerprint import extract_fingerprints

# Pitfall 3: the explicit high limit that defeats gh's silent default of 30.
_LIST_LIMIT = "500"
_LIST_TIMEOUT_SECONDS = 60.0


def list_open_issue_bodies(owner_repo: str, repo_path: Path) -> list[dict]:
    """Return ``[{number, url, body}, ...]`` for OPEN issues, via gh.

    Runs ``gh issue list -R OWNER/REPO --state open --json number,url,body
    --limit 500`` through run_tool with a full env (Pitfall 4) + 60s timeout.
    Degrades to ``[]`` on gh-missing/timeout/unauthenticated and on any JSON
    parse error (mirrors osv.py's degrade-to-empty contract) — never raises.
    """
    res = run_tool(
        ["gh", "issue", "list", "-R", owner_repo, "--state", "open",
         "--json", "number,url,body", "--limit", _LIST_LIMIT],
        env=dict(os.environ),
        cwd=repo_path,
        timeout_seconds=_LIST_TIMEOUT_SECONDS,
    )
    if res.returncode in (EXEC_FAILED, TIMED_OUT):
        return []
    # gh emits non-zero (e.g. 4) on auth failure with no JSON body; the parse
    # guard below also catches that path. Parse defensively regardless of rc so
    # a vuln-style non-zero-but-valid-JSON case is still honored.
    try:
        parsed = json.loads(res.stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def fetch_open_fingerprints(repo_path: Path, *, owner_repo: str) -> set[str]:
    """Recover the set of fingerprint markers embedded in OPEN issue bodies.

    Lists OPEN issues (:func:`list_open_issue_bodies`) and substring-extracts
    every embedded ``arch-fingerprint`` marker from each body (D-14 client-side
    grep — the marker is invisible to GitHub search). Returns an empty set on
    any failure; never raises.
    """
    fingerprints: set[str] = set()
    for issue in list_open_issue_bodies(owner_repo, repo_path):
        fingerprints |= extract_fingerprints(issue.get("body", ""))
    return fingerprints


def is_duplicate(fingerprint: str, open_fingerprints: set[str]) -> bool:
    """True iff ``fingerprint`` already appears among the OPEN-issue markers.

    The D-16 skip-on-match decision: a match means the finding is already filed
    and open, so the draft is skipped (never edited/commented). A miss means it
    will be filed.
    """
    return fingerprint in open_fingerprints


def find_duplicate(fingerprint: str, open_issues: list[dict]) -> str | None:
    """Plan-named variant: return the URL of an OPEN issue carrying the marker.

    Substring-matches the fingerprint marker over each issue body (D-14/D-16).
    Returns the matching issue's ``url`` if no open issue carries it, ``None``.

    WR-04: a marker match is ALWAYS a duplicate (skip), even when the gh JSON
    payload omits ``url`` (the payload is parsed defensively as a plain dict, so
    ``url`` may be missing). Returning ``None`` on a real match would let the
    caller (``run_issues`` step [4], which treats only a non-``None`` return as a
    duplicate) RE-FILE a genuinely-open duplicate. So we return a url-or-
    placeholder: the function never returns ``None`` once the marker matched.
    """
    for issue in open_issues:
        if fingerprint in extract_fingerprints(issue.get("body", "")):
            return issue.get("url") or "(open issue, url unavailable)"
    return None


__all__ = [
    "fetch_open_fingerprints",
    "find_duplicate",
    "is_duplicate",
    "list_open_issue_bodies",
]
