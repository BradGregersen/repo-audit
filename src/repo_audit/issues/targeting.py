"""Origin -> owner/repo resolution + the D-09/D-10 target-identity guard.

This is the first of the two outward-read subprocess seams of ``repo-audit issues``
(``dedup`` is the other). It owns:

  * **D-09 origin-remote targeting** — the repo we file against is resolved from
    the sidecar-producing dir's ``origin`` remote, never guessed from a name.
    ``parse_origin`` parses all four GitHub URL forms (https/.git, ssh-scp,
    https-no-.git, ssh-url) with one anchored regex (no eval — Security V5).
  * **D-10 target-identity guard** — before ANY downstream filing (Plan 04), the
    resolved origin owner/repo must match the repo actually scanned. This blocks
    the accidental wrong-repo write WITHOUT name-special-casing repo-audit:
    the self-file (dogfood) case passes precisely because target == scanned.

Every ``git``/``gh`` shell-out routes through :func:`run_tool` (shell=False,
``list[str]`` argv, TypeError on a ``str`` argv) with a full ``dict(os.environ)``
so ``gh`` finds ``~/.config/gh/hosts.yml`` (Pitfall 4 — a stripped env reads as
unauthenticated rc=4 even when the user IS authed) and an explicit
``timeout_seconds`` (T-19-07 DoS). No function here ever raises across its
boundary except the deliberate :class:`IdentityGuardError` the guard signals on a
mismatch, and a programming-error ``TypeError`` from ``run_tool`` on a bad argv.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from repo_audit.adapters.toolops import EXEC_FAILED, run_tool

# Verified against gh 2.93.0 / git 2.x (RESEARCH Pattern 2). Anchored, no eval.
# Captures OWNER and REPO across all four remote URL forms:
#   git@github.com:OWNER/REPO.git           (ssh-scp)
#   https://github.com/OWNER/REPO.git       (https + .git)
#   https://github.com/OWNER/REPO           (https, no .git)
#   ssh://git@github.com/OWNER/REPO.git     (ssh-url)
_ORIGIN_RE = re.compile(r"github\.com[:/]([^/]+)/(.+?)(?:\.git)?/?$")

# gh returns unauthenticated as exit code 4 (RESEARCH §Common gh Commands).
_GH_UNAUTHENTICATED = 4

_GIT_TIMEOUT_SECONDS = 30.0
_GH_TIMEOUT_SECONDS = 30.0


class IdentityGuardError(RuntimeError):
    """Raised when the resolved target does not match the scanned repo (D-10).

    Signals the wrong-repo guard tripping — the only deliberate raise in this
    module. The caller (the ``issues`` CLI command, Plan 04) catches it and
    refuses to file anything, surfacing the clear mismatch reason.
    """


@dataclass(frozen=True)
class TargetResolution:
    """Outcome of resolving (and optionally identity-checking) a file target.

    ``owner_repo`` is ``"Owner/Repo"`` when the origin parsed; ``ok`` is the
    overall verdict; ``reason`` carries the actionable note on any failure
    (git/gh missing, no/non-GitHub origin, unauthenticated, wrong-repo) and is
    ``None`` on success.
    """

    owner_repo: str | None
    ok: bool
    reason: str | None = None


def parse_origin(origin_url: str) -> str | None:
    """Parse a git origin URL to ``"Owner/Repo"`` (all four GitHub forms).

    Returns ``None`` for a non-GitHub remote (e.g. gitlab) or an unparseable
    URL — the caller folds that into a clear "non-GitHub remote (D-09)" note.
    The regex is anchored and never eval'd (Security V5).
    """
    match = _ORIGIN_RE.search(origin_url.strip())
    if match is None:
        return None
    owner, repo = match.group(1), match.group(2)
    return f"{owner}/{repo}"


# Plan-prose alias: returns the same value as a tuple for callers that want the
# split parts. ``parse_origin`` (the scaffold-bound name) is the primary API.
def parse_owner_repo(origin_url: str) -> tuple[str, str] | None:
    """Plan-named variant of :func:`parse_origin` returning ``(owner, repo)``."""
    owner_repo = parse_origin(origin_url)
    if owner_repo is None:
        return None
    owner, repo = owner_repo.split("/", 1)
    return (owner, repo)


def _read_origin(repo_path: Path) -> tuple[str | None, str | None]:
    """Return ``(origin_url, error_reason)`` via ``git remote get-url origin``.

    On a missing git binary -> ``(None, "git not on PATH")``; on an empty/blank
    origin -> ``(None, "no git origin (D-09)")``. Never raises (T-19-07).
    """
    res = run_tool(
        ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
        env=dict(os.environ),
        cwd=repo_path,
        timeout_seconds=_GIT_TIMEOUT_SECONDS,
    )
    if res.returncode == EXEC_FAILED:
        return (None, "git not on PATH")
    origin = (res.stdout or "").strip()
    if not origin:
        return (None, "no git origin (D-09)")
    return (origin, None)


def resolve_target(repo_path: Path) -> TargetResolution:
    """Resolve ``repo_path``'s origin to ``Owner/Repo`` and run the D-10 guard.

    1. ``git remote get-url origin`` (via run_tool, full env, 30s) — missing
       git / no origin / non-GitHub remote each fold to ``ok=False`` with a
       clear ``reason``, never a raise.
    2. ``gh repo view OWNER/REPO --json nameWithOwner -q .nameWithOwner`` (repo
       is a POSITIONAL arg, NOT ``-R``) — the canonical identity probe. gh
       missing -> "gh not on PATH (D-08)"; rc==4 -> "gh unauthenticated — run
       gh auth login (D-08)"; a canonical ``nameWithOwner`` that differs from
       the origin-parsed slug -> the wrong-repo guard reason (D-10).

    There is NO by-name special-casing of repo-audit: dogfooding passes
    because the target IS the scanned target (D-10).
    """
    origin, err = _read_origin(repo_path)
    if err is not None:
        return TargetResolution(owner_repo=None, ok=False, reason=err)

    owner_repo = parse_origin(origin)  # origin is non-None when err is None
    if owner_repo is None:
        return TargetResolution(
            owner_repo=None, ok=False, reason="non-GitHub remote (D-09)"
        )

    res = run_tool(
        ["gh", "repo", "view", owner_repo, "--json", "nameWithOwner",
         "-q", ".nameWithOwner"],
        env=dict(os.environ),
        cwd=repo_path,
        timeout_seconds=_GH_TIMEOUT_SECONDS,
    )
    if res.returncode == EXEC_FAILED:
        return TargetResolution(
            owner_repo=owner_repo, ok=False, reason="gh not on PATH (D-08)"
        )
    if res.returncode == _GH_UNAUTHENTICATED:
        return TargetResolution(
            owner_repo=owner_repo,
            ok=False,
            reason="gh unauthenticated — run gh auth login (D-08)",
        )

    canonical = (res.stdout or "").strip()
    if canonical and canonical.lower() != owner_repo.lower():
        return TargetResolution(
            owner_repo=owner_repo,
            ok=False,
            reason=(
                f"wrong-repo guard: sidecar origin {owner_repo} "
                f"!= gh target {canonical} (D-10)"
            ),
        )
    return TargetResolution(owner_repo=owner_repo, ok=True, reason=None)


def assert_target_matches(repo_path: Path, *, scanned_slug: str) -> str:
    """Enforce the D-10 identity guard against the SCANNED repo slug.

    Resolves ``repo_path``'s origin to ``Owner/Repo`` and requires the repo
    half to equal ``scanned_slug`` (case-insensitive). On a mismatch — the
    accidental wrong-repo write — raises :class:`IdentityGuardError` with a
    clear reason and files nothing. On a match (the self-file/dogfood case,
    target == scanned) returns the resolved ``Owner/Repo``.

    Resolution uses the repo's real ``origin`` remote (via run_tool). This guard
    intentionally does NOT require ``gh`` — the origin remote is the trust
    anchor for the scanned-vs-target match; the gh ``nameWithOwner`` cross-check
    is the second, online layer in :func:`resolve_target`.
    """
    origin, err = _read_origin(repo_path)
    if err is not None:
        raise IdentityGuardError(err)

    owner_repo = parse_origin(origin)  # origin non-None when err is None
    if owner_repo is None:
        raise IdentityGuardError("non-GitHub remote (D-09)")

    repo_slug = owner_repo.split("/", 1)[1]
    if repo_slug.lower() != scanned_slug.lower():
        raise IdentityGuardError(
            f"wrong-repo guard: origin {owner_repo} (repo '{repo_slug}') "
            f"!= scanned slug '{scanned_slug}' (D-10)"
        )
    return owner_repo


__all__ = [
    "IdentityGuardError",
    "TargetResolution",
    "assert_target_matches",
    "parse_origin",
    "parse_owner_repo",
    "resolve_target",
]
