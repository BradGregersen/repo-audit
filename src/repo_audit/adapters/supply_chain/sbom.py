"""SUP-02 — Syft SBOM artifact generation (Plan 12-04, Wave 1).

A generated SBOM is the supply-chain provenance artifact for a scanned repo; it
also feeds Plan 12-03's offline license-risk derivation. ``generate_sbom``
resolves the VENDORED Syft (Plan 12-01 shipped ``vendor/syft/syft``) via the
project's tool-resolution ladder (vendor wins — D-06-10), runs it OFFLINE to
emit a CycloneDX JSON document, and returns the artifact PATH for the wiring
plan (12-05) to stamp into ``ReportMeta``. The report references the SBOM by
path; the SBOM document is NEVER inlined onto the result (D-12-07).

READ-ONLY CONTRACT (the hard constraint of this plan — Pitfall 6 / T-12-04-TAMP):
    The SBOM lands in the repo-audit TOOL repo's own gitignored
    ``reports/`` dir:

        {repo-audit}/reports/<slug>-sbom-<date>.json

    — OUTSIDE the scanned target repo. NOTHING may be written under the target
    repo: the orchestrator's post-flight ``diff_git_status`` tripwire
    (``scan_runner``) fires if any file appears under the target tree after a
    scan. That tripwire is the BACKSTOP; the PRIMARY guard is here — the derived
    ``out_path`` is asserted to be NOT under ``repo_path`` before any directory
    is created or Syft is invoked.

DEGRADE HONESTLY (SAFE-08 / D-12-04 / T-12-04-AVAIL):
    * Syft not resolvable (vendor + PATH miss) → ``status='unavailable'``, NO
      write attempted, no raise (Pitfall 5).
    * Syft runs but produces no output file (no catalogable packages) or exits
      via the exec-failed sentinel → ``status='unavailable'``; the scan still
      completes; nothing is written under the target repo.
    * Syft times out → ``status='timeout'``.

``generate_sbom`` NEVER raises across its boundary (mirrors the ``OsvResult`` /
``HistoryResult`` never-raise contract): every failure mode folds into an
``SbomResult`` status + notes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal, Optional

from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.meta.paths import _repo_repo_root
from repo_audit.meta.slug import repo_slug

SbomStatus = Literal["ok", "unavailable", "timeout"]

# Syft can walk a large tree's package catalogers; a generous bound mirrors the
# v2.0 "cost no object" stance for deep-audit collectors while still guaranteeing
# the scan never hangs (run_tool enforces SIGTERM→SIGKILL on expiry).
_SYFT_TIMEOUT_SECONDS: float = 300.0

# Truncate captured stderr in notes so a verbose Syft failure does not bloat the
# scope ledger / SUMMARY. Value-agnostic (Syft stderr carries no secret).
_STDERR_NOTE_CAP: int = 240


@dataclass
class SbomResult:
    """The never-raise envelope returned by :func:`generate_sbom`.

    Mirrors the ``adapters/sca/osv.OsvResult`` never-raise contract. The
    carrier the wiring plan (12-05) stamps onto ``ReportMeta`` — it references
    the SBOM by ``sbom_path`` ONLY. There is intentionally NO field carrying the
    SBOM document content (D-12-07: reference by path, never inline).
    """

    status: SbomStatus = "ok"
    sbom_path: Optional[Path] = None
    notes: str = ""


def _default_out_path(repo_path: Path, scan_date: date) -> Path:
    """Derive the tool-local ``reports/<slug>-sbom-<date>.json`` artifact path.

    Mirrors ``meta.paths.fleet_report_paths`` / ``state_report_paths``: the file
    lands in the repo-audit repo's own gitignored ``reports/`` dir, with
    the same-day ``-2``/``-3``/... collision suffix so a re-run never silently
    overwrites a prior SBOM. Does NOT create the directory — the caller does,
    only AFTER the not-under-repo guard passes.
    """
    out_dir = _repo_repo_root() / "reports"
    stem = f"{repo_slug(repo_path)}-sbom-{scan_date.isoformat()}"
    candidate = out_dir / f"{stem}.json"
    if candidate.exists():
        n = 2
        while True:
            cand = out_dir / f"{stem}-{n}.json"
            if not cand.exists():
                return cand
            n += 1
    return candidate


def _is_under(child: Path, parent: Path) -> bool:
    """True iff ``child`` resolves to ``parent`` or one of its descendants.

    Boundary-safe containment check (NOT a string-prefix test, which would treat
    a sibling ``/repo-2`` as inside ``/repo``). Used as the PRIMARY read-only
    guard: the SBOM out_path must NOT be under the scanned repo.
    """
    child_r = child.resolve()
    parent_r = parent.resolve()
    return child_r == parent_r or parent_r in child_r.parents


def generate_sbom(
    repo_path: Path,
    out_path: Optional[Path] = None,
    *,
    env: Optional[dict[str, str]] = None,
    scan_date: Optional[date] = None,
) -> SbomResult:
    """SUP-02: generate a CycloneDX SBOM artifact OUTSIDE the target repo.

    Args:
        repo_path: the repo to catalog. Syft walks it OFFLINE (no network).
        out_path: explicit artifact destination (the wiring plan supplies one).
            When ``None``, it is derived as
            ``{repo-audit}/reports/<slug>-sbom-<scan_date>.json`` (mirrors
            the fleet/state path convention, including same-day collision
            suffixing). Either way the path is GUARANTEED to be outside
            ``repo_path`` (the read-only contract; Pitfall 6).
        env: the child environment for the Syft invocation (passed verbatim to
            ``run_tool``). Defaults to an empty mapping when omitted — Syft needs
            no special env for offline cataloging.
        scan_date: the date used to stamp the derived ``out_path`` filename.
            Only consulted when ``out_path`` is ``None``; defaults to
            ``date.today()``.

    Returns:
        An :class:`SbomResult`. ``status='ok'`` with ``sbom_path`` set when Syft
        wrote the artifact; ``status='unavailable'`` when Syft is absent or
        produced no output (no catalogable packages) — NO target-repo write in
        either case; ``status='timeout'`` when the run exceeded the bound. Never
        raises. The SBOM document is never inlined onto the result.
    """
    repo_path = Path(repo_path)

    # 1. Resolve the vendored Syft (vendor/syft/syft wins — D-06-10). A miss →
    #    unavailable with NO write attempted (Pitfall 5 / T-12-04-AVAIL).
    syft = resolve_tool("syft", repo_path)
    if syft is None:
        return SbomResult(
            status="unavailable",
            notes="syft not found (vendor + PATH miss)",
        )

    # 2. Resolve the artifact destination. When the caller did not supply one,
    #    derive the tool-local reports/ path (NEVER under the target repo).
    if out_path is None:
        out_path = _default_out_path(repo_path, scan_date or date.today())
    else:
        out_path = Path(out_path)

    # PRIMARY read-only guard (defense-in-depth ahead of the post-flight
    # diff_git_status backstop — Pitfall 6 / T-12-04-TAMP): the SBOM must NOT
    # land under the scanned repo. Refuse rather than risk a target-repo write.
    if _is_under(out_path, repo_path):
        return SbomResult(
            status="unavailable",
            notes=(
                "refusing to write SBOM under the scanned repo (read-only "
                "contract); out_path must live outside the target tree"
            ),
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 3. Invoke Syft OFFLINE to emit CycloneDX JSON to out_path (CITED
    #    anchore/syft offline argv). shell=False, list[str] via the single
    #    run_tool seam.
    inv = run_tool(
        [str(syft), str(repo_path), "-o", f"cyclonedx-json={out_path}"],
        env=env if env is not None else {},
        cwd=repo_path,
        timeout_seconds=_SYFT_TIMEOUT_SECONDS,
    )

    # 4. Map the invocation outcome to an honest status.
    if inv.returncode == TIMED_OUT:
        return SbomResult(
            status="timeout",
            notes=f"syft exceeded {_SYFT_TIMEOUT_SECONDS:.0f}s",
        )

    # Exec-failed (binary vanished) OR no artifact on disk (no catalogable
    # packages / syft errored) → unavailable. The scan still completes and
    # nothing was written under the target repo. (Pitfall 5 / T-12-04-AVAIL.)
    if inv.returncode == EXEC_FAILED or not out_path.is_file():
        note = (inv.stderr or "").strip()[:_STDERR_NOTE_CAP]
        return SbomResult(
            status="unavailable",
            notes=(
                "syft produced no SBOM (no catalogable packages or syft failed)"
                + (f": {note}" if note else "")
            ),
        )

    # Reference the artifact by PATH only — the SBOM document is never inlined
    # onto the result (D-12-07).
    return SbomResult(status="ok", sbom_path=out_path)


__all__ = ["SbomResult", "SbomStatus", "generate_sbom"]
