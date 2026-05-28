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

from datetime import date
from pathlib import Path

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
