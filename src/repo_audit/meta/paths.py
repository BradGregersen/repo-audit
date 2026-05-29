"""Output path derivation + D-15 directory creation discipline + Pitfall 4 collision handling.

The MD/JSON pair lives at:
    {target-repo}/docs/state-reports/{slug}-state-report-{YYYY-MM-DD}.md
    {target-repo}/docs/state-reports/{slug}-state-report-{YYYY-MM-DD}.json

The directory is NOT created here -- the caller (render_and_write) creates it
AFTER both buffers have passed secret-lint (Plan 05). This ordering matters:
if secret-lint fires, the target repo must remain untouched (no orphan
`docs/state-reports/` directory left behind).

Pitfall 4: if {stem}.md already exists (second run same day), append -2/-3/...
so a fleet sweep does not require human intervention.
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from pydantic import ValidationError

from repo_audit.meta.slug import repo_slug


def state_report_paths(repo_path: Path, scan_date: date) -> tuple[Path, Path]:
    """Return (md_path, json_path). Does NOT create directories.

    Caller is responsible for `md_path.parent.mkdir(parents=True, exist_ok=True)`
    AFTER secret-lint passes (Plan 05 wires this).
    """
    slug = repo_slug(repo_path)
    out_dir = Path(repo_path) / "docs" / "state-reports"
    stem = f"{slug}-state-report-{scan_date.isoformat()}"
    md = out_dir / f"{stem}.md"
    js = out_dir / f"{stem}.json"
    if md.exists() or js.exists():
        # Pitfall 4 + 01-REVIEW Finding 1: same-day re-run; append -2, -3, ...
        # check BOTH .md and .json so we never silently overwrite a sibling sidecar.
        n = 2
        while True:
            cand_md = out_dir / f"{stem}-{n}.md"
            cand_js = out_dir / f"{stem}-{n}.json"
            if not (cand_md.exists() or cand_js.exists()):
                return cand_md, cand_js
            n += 1
    return md, js


def _repo_repo_root() -> Path:
    """Resolve the repo-audit repo's own root (which owns ``reports/``).

    The fleet artifacts land in the TOOL's repo, not in any scanned target repo:
    ``{repo-audit}/reports/fleet-{date}.json`` (``.gitignore`` carries
    ``reports/`` — D-05-02 / constraint: JSON fleet artifacts are gitignored).

    Resolution walks up from this module's location looking for the repo root
    marker (a ``pyproject.toml`` whose ``[project].name`` is ``repo-audit``).
    This is correct for the supported install path (``pipx/uv tool install
    --editable .`` from a local clone — CLAUDE.md): the editable install leaves
    the package importable from inside the clone, so ``__file__`` sits under
    ``{clone}/src/repo_audit/meta/paths.py`` and parents[3] is the clone.

    Falls back to ``parents[3]`` (the structural repo root) if no matching
    marker is found while walking up — preserves a sane default rather than
    raising, so a fleet sweep never aborts on path resolution alone.
    """
    here = Path(__file__).resolve()
    # paths.py -> meta -> repo_audit -> src -> {repo root}
    structural_root = here.parents[3]
    for candidate in (structural_root, *structural_root.parents):
        pyproject = candidate / "pyproject.toml"
        if pyproject.is_file():
            try:
                text = pyproject.read_text(encoding="utf-8")
            except OSError:
                continue
            if 'name = "repo-audit"' in text:
                return candidate
    return structural_root


def fleet_report_paths(root: Path, gen_date: date) -> tuple[Path, Path]:
    """Return (fleet_json_path, fleet_dashboard_md_path). Does NOT create dirs.

    Both land in the repo-audit repo's own gitignored ``reports/`` dir:
        {repo-audit}/reports/fleet-{YYYY-MM-DD}.json
        {repo-audit}/reports/fleet-dashboard-{YYYY-MM-DD}.md

    ``root`` (the sweep root being audited) is accepted for API symmetry and
    future provenance use; the OUTPUT location is always the tool's own
    ``reports/`` dir regardless of which directory is swept.

    Same-day collision handling mirrors ``state_report_paths``: if either the
    ``.json`` or ``.md`` for today already exists, append ``-2``/``-3``/... so a
    re-run never silently overwrites a prior sweep's pair. The directory is the
    caller's responsibility to create (Plan 05-05 wires the write).
    """
    _ = root  # accepted for API symmetry / future provenance; output is tool-local
    out_dir = _repo_repo_root() / "reports"
    stem = f"fleet-{gen_date.isoformat()}"
    dash_stem = f"fleet-dashboard-{gen_date.isoformat()}"
    js = out_dir / f"{stem}.json"
    md = out_dir / f"{dash_stem}.md"
    if js.exists() or md.exists():
        n = 2
        while True:
            cand_js = out_dir / f"{stem}-{n}.json"
            cand_md = out_dir / f"{dash_stem}-{n}.md"
            if not (cand_js.exists() or cand_md.exists()):
                return cand_js, cand_md
            n += 1
    return js, md


def find_prior_sidecar(repo_path: Path, today: date) -> Path | None:
    """Return the most-recent prior JSON sidecar dated strictly before today.

    Plan 05-01 / TREND-01 ("most-recent prior") with the CONTEXT.md Claude's-
    Discretion steer "before today" (05-CONTEXT.md:45): re-running a scan twice
    in one day compares against the previous day, not the report just written.

    Reads the AUTHORITATIVE ``meta.scan_date`` from inside each sidecar (NOT the
    filename — filenames carry a -2/-3 collision suffix and could be hand-edited,
    so the in-payload date is the source of truth).

    Security (T-05-01, Tampering): a target repo's ``docs/state-reports/*.json``
    is hand-editable untrusted input. Each file is parsed via
    ``ScanReport.model_validate_json`` (extra='forbid'); any
    ``ValidationError`` / ``json.JSONDecodeError`` / ``OSError`` skips that file
    (treated as not-a-usable-baseline) rather than crashing the scan.

    Returns:
        The Path of the JSON sidecar with the maximum ``meta.scan_date`` that is
        strictly ``< today``, or ``None`` when no usable prior sidecar exists
        (no dir, no JSON, only today's sidecars, all unparseable).
    """
    # Deferred import: report.py pulls in the agent schema chain; keep meta.paths
    # cheap to import for callers (e.g. detect) that never touch sidecars.
    from repo_audit.schema.report import ScanReport

    out_dir = Path(repo_path) / "docs" / "state-reports"
    if not out_dir.is_dir():
        return None

    best_path: Path | None = None
    best_date: date | None = None
    for candidate in out_dir.glob("*.json"):
        try:
            text = candidate.read_text(encoding="utf-8")
            report = ScanReport.model_validate_json(text)
        except (ValidationError, json.JSONDecodeError, OSError, ValueError):
            # Corrupt / hostile / unreadable sidecar → skip; no usable baseline
            # from this file. Does NOT crash the scan (T-05-01 mitigation).
            continue
        sidecar_date = report.meta.scan_date
        if sidecar_date >= today:
            # Same-day re-run (Pitfall 3) or a future-dated sidecar — not a
            # prior baseline.
            continue
        if best_date is None or sidecar_date > best_date:
            best_date = sidecar_date
            best_path = candidate
    return best_path
