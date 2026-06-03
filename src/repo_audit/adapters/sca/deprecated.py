"""SCA-04 — deprecated/abandoned package handling: INFO CONTEXT ONLY (D-12-08).

D-12-08 (the deliberate D-07-08 noise-defusing split): deprecated/abandoned
packages are REAL signal but must NEVER become fix-generating findings the way a
CVE/MAL advisory does. Reporting "upgrade to X" for every stale transitive dep is
exactly the "known noise generator" D-07-08 warned against. So this module
surfaces deprecated packages as an INFO CONTEXT envelope — a count plus the named
package list — NOT a list of actionable Findings (T-12-03-NOISE: accepted, info
only).

The deprecated SIGNAL source is osv's deprecated-package pass. PITFALL-1
(network/offline collision): that pass consults deps.dev over the network in an
otherwise pinned-offline phase. If it cannot complete offline (exec-failed /
timeout / empty under offline) the pass degrades to ``status='unavailable'`` with
a network-dependency note and the scan still completes — never raises, never
hangs (T-12-03-NET).

If the renderer contract ever forces a Finding object, the ONLY permitted shape
is ``severity='info'`` with ``parsed_value={'presence_only': True}`` (the SAFE-03
ceiling). The context envelope is strongly preferred; ``findings`` stays empty by
default.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional

from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Finding

DeprecatedStatus = Literal["ok", "unavailable", "timeout"]

# osv deprecated pass timeout (matches the osv collector's 120s ceiling).
_DEPRECATED_TIMEOUT_SECONDS: float = 120.0


@dataclass
class DeprecatedResult:
    """INFO-context envelope for deprecated packages (NOT fix-generating findings).

    ``deprecated_packages`` + ``count`` ARE the deliverable — the named list of
    abandoned packages surfaced as context. ``findings`` stays EMPTY by default
    (D-12-08); if the renderer ever requires a Finding it is at most
    ``severity='info'``/``presence_only`` (SAFE-03), never major/minor.
    """

    deprecated_packages: list[str] = field(default_factory=list)
    count: int = 0
    findings: list[Finding] = field(default_factory=list)
    status: DeprecatedStatus = "ok"
    notes: str = ""


def _names_from_records(records: list[Any]) -> list[str]:
    """Pull the names of records flagged ``deprecated=True`` (Wave-0 test shape).

    The Wave-0 contract passes ``[{'name','version','deprecated': True}, ...]``.
    A record is counted only when it explicitly carries ``deprecated`` truthy.
    """
    names: list[str] = []
    for rec in records:
        if isinstance(rec, dict) and rec.get("deprecated") and rec.get("name"):
            name = rec["name"]
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
    return names


def _osv_deprecated_argv(binary: Path, repo_path: Path) -> list[str]:
    """Build the osv deprecated-package pass argv (deps.dev-backed).

    Network-dependent (Pitfall 1): consults deps.dev for deprecation status.
    Read-only ``scan source`` — does not write into the target repo.
    """
    return [
        str(binary),
        "scan",
        "source",
        "--recursive",
        "--experimental-flag-deprecated-packages",
        "--format",
        "json",
        str(repo_path),
    ]


def _names_from_osv_json(stdout: str) -> list[str]:
    """Best-effort parse of deprecated package names from osv JSON.

    Tolerant of shape drift: walks ``results[].packages[].package`` and keeps any
    package marked deprecated (``deprecated`` / ``isDeprecated`` truthy). Returns
    an empty list on any parse miss — the caller maps empty-under-offline to
    ``unavailable`` rather than asserting "nothing is deprecated".
    """
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    names: list[str] = []
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        for pkg_entry in result.get("packages") or []:
            if not isinstance(pkg_entry, dict):
                continue
            pkg = pkg_entry.get("package") or {}
            if not isinstance(pkg, dict):
                continue
            if pkg_entry.get("deprecated") or pkg.get("isDeprecated") or pkg.get("deprecated"):
                name = pkg.get("name")
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
    return names


def _from_repo(repo_path: Path, env: Optional[dict[str, str]]) -> DeprecatedResult:
    """Run the osv deprecated pass over ``repo_path`` (runtime-wiring path)."""
    binary = resolve_tool("osv-scanner", repo_path)
    if binary is None:
        return DeprecatedResult(
            status="unavailable",
            notes="osv-scanner not found — deprecated context not derived",
        )

    invocation = run_tool(
        _osv_deprecated_argv(binary, repo_path),
        env=env or {},
        cwd=repo_path,
        timeout_seconds=_DEPRECATED_TIMEOUT_SECONDS,
    )
    if invocation.returncode == TIMED_OUT:
        return DeprecatedResult(
            status="timeout",
            notes=f"osv deprecated pass exceeded {_DEPRECATED_TIMEOUT_SECONDS:.0f}s",
        )
    if invocation.returncode == EXEC_FAILED:
        return DeprecatedResult(
            status="unavailable",
            notes=(
                "osv deprecated pass could not execute — likely offline "
                "(deps.dev network-dependent, Pitfall 1)"
            ),
        )

    names = _names_from_osv_json(invocation.stdout)
    if not names:
        # Empty under offline is indistinguishable from "deps.dev unreachable";
        # disclose unavailable rather than asserting nothing is deprecated.
        return DeprecatedResult(
            status="unavailable",
            notes=(
                "osv deprecated pass returned no deprecation data — offline / "
                "deps.dev unreachable (Pitfall 1); scan completed"
            ),
        )
    return DeprecatedResult(
        deprecated_packages=sorted(set(names)),
        count=len(set(names)),
        status="ok",
    )


def collect_deprecated(source: Any, *, env: Optional[dict[str, str]] = None) -> DeprecatedResult:
    """Surface deprecated packages as INFO CONTEXT (never fix-generating findings).

    Args:
        source: EITHER a list of package records
            (``[{'name','version','deprecated': bool}, ...]`` — the Wave-0 test
            shape) OR a repo ``Path``/``str`` to run the osv deprecated pass over
            (the runtime-wiring shape).
        env: child environment for the osv pass (repo-path mode only).

    Returns:
        A :class:`DeprecatedResult` — a named list + count of deprecated
        packages as INFO context. ``findings`` is EMPTY (D-12-08: no actionable
        findings). Degrades to ``status='unavailable'`` when the source is
        missing or the pass cannot complete offline. Never raises.
    """
    if isinstance(source, (str, Path)):
        return _from_repo(Path(source), env)

    if isinstance(source, list):
        names = sorted(set(_names_from_records(source)))
        return DeprecatedResult(
            deprecated_packages=names,
            count=len(names),
            status="ok",
        )

    # Unknown input shape — degrade honestly.
    return DeprecatedResult(
        status="unavailable",
        notes=f"unsupported source type {type(source).__name__!r}",
    )


__all__ = ["DeprecatedResult", "DeprecatedStatus", "collect_deprecated"]
