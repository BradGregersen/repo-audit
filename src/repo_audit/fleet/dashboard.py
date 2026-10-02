"""Fleet dashboard renderer (Plan 05-05 / FLEET-03 / SC-4).

Renders a :class:`FleetSnapshot` into the triage markdown dashboard
(``fleet-dashboard-{date}.md``) and writes the snapshot JSON
(``fleet-{date}.json``), routing BOTH buffers through the LOCKED lint
chokepoint before either touches disk (RESEARCH Pattern 4 / CONTEXT.md:86 /
T-05-08).

Chokepoint ordering (mirrors render/renderer.py exit codes — the contract):
    1. build both buffers in memory (markdown + JSON)
    2. lint_buffer(...) on both (secret-lint, D-07)        -> SecretsDetected -> rc 2
    3. completion_honesty_lint(..., partial=False) on both -> Violation      -> rc 3
    4. only if both pass: mkdir parent + write both         -> rc 0

On a lint refusal NOTHING is written (the reports/ dir stays untouched on the
refusal path — the same Pitfall-8 discipline the per-repo renderer follows).

partial=False for the fleet buffers: the dashboard is a complete roll-up of
every discovered repo (failures included as rows), so the completion-honesty
"all/every/complete" guard is a no-op here — but the buffer is STILL routed
through it (defense in depth; the chokepoint is never bypassed).

Triage ordering (D-05-08/10): the rows handed to the template are re-ordered —
failed rows pinned to the VERY TOP (a repo you can't scan is the most urgent),
then ok rows worst-health-first (blocker desc, critical desc, major desc). The
snapshot's canonical ``repos`` order (discovery order, FLEET-01) is NOT mutated
— the JSON artifact preserves it; only the markdown view is re-ranked.
"""
from __future__ import annotations

import sys
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from repo_audit.render.completion_honesty import (
    CompletionHonestyViolation,
    completion_honesty_lint,
    format_completion_honesty_diagnostic,
)
from repo_audit.render.secret_lint import (
    SecretsDetected,
    format_diagnostic,
    lint_buffer,
)
from repo_audit.schema.fleet import FleetRepoRow, FleetSnapshot


def _make_env() -> Environment:
    """Jinja env mirroring renderer.py:71 (PackageLoader, markdown not HTML).

    Reuses the SAME loader/undefined discipline as the per-repo renderer so the
    fleet template lives alongside ``state_report.md.j2`` and benefits from the
    same StrictUndefined typo-catch.
    """
    return Environment(
        loader=PackageLoader("repo_audit", "render/templates"),
        autoescape=False,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def _health_sort_key(row: FleetRepoRow) -> tuple[int, int, int]:
    """Worst-health-first sort key for an OK row (D-05-08).

    Sums blocker / critical / major across the row's per-dimension counts and
    returns a tuple negated so a plain ascending sort puts the worst repos
    first (most blockers, then most criticals, then most majors).
    """
    blockers = critical = major = 0
    for sev in row.severity_by_dimension.values():
        blockers += sev.get("blocker", 0)
        critical += sev.get("critical", 0)
        major += sev.get("major", 0)
    return (-blockers, -critical, -major)


def _order_rows(snapshot: FleetSnapshot) -> list[FleetRepoRow]:
    """Triage ordering: failed rows pinned top (D-05-10), then ok rows
    worst-health-first (D-05-08). Does NOT mutate ``snapshot.repos``."""
    failed = [r for r in snapshot.repos if r.status == "failed"]
    ok = [r for r in snapshot.repos if r.status != "failed"]
    ok_ranked = sorted(ok, key=_health_sort_key)
    return failed + ok_ranked


def render_fleet_dashboard(snapshot: FleetSnapshot, md_path: Path) -> int:
    """Render the dashboard markdown + write the JSON, via the lint chokepoint.

    Args:
        snapshot: The :class:`FleetSnapshot` to render.
        md_path: Target path for the markdown dashboard
            (``…/reports/fleet-dashboard-{date}.md``). The JSON sidecar path is
            derived by swapping the ``fleet-dashboard-`` stem prefix for
            ``fleet-`` and the suffix for ``.json`` (the pair
            ``fleet_report_paths`` produces).

    Returns:
        0 on success (both buffers passed lint, both files written),
        2 if secret-lint refused (mirrors renderer.py / D-06 — nothing written),
        3 if completion-honesty refused (mirrors renderer.py / D-32).
    """
    md_path = Path(md_path)
    json_path = md_path.with_name(
        md_path.name.replace("fleet-dashboard-", "fleet-", 1)
    ).with_suffix(".json")

    # ----- Build BOTH buffers in memory (no I/O yet). -----
    ordered_rows = _order_rows(snapshot)
    env = _make_env()
    template = env.get_template("fleet_dashboard.md.j2")
    markdown_buf = template.render(snapshot=snapshot, ordered_rows=ordered_rows)
    json_buf = snapshot.model_dump_json(indent=2)

    # ----- LOCKED chokepoint on BOTH buffers BEFORE any write (T-05-08). -----
    # The sweep root is the operator's own directory, printed by repo-audit
    # itself; a random-looking name in it (a UUID) must not read as a secret.
    # Only that exact string is masked, and only in what is scanned.
    sweep_root = str(snapshot.sweep_root)
    try:
        lint_buffer(
            markdown_buf.replace(sweep_root, "<sweep-root>"),
            buffer_name="fleet-dashboard",
        )
        lint_buffer(
            json_buf.replace(sweep_root, "<sweep-root>"), buffer_name="fleet-json"
        )
        completion_honesty_lint(
            markdown_buf, partial=False, buffer_name="fleet-dashboard"
        )
        completion_honesty_lint(json_buf, partial=False, buffer_name="fleet-json")
    except SecretsDetected as e:
        print(format_diagnostic(e.hits, e.buffer_name), file=sys.stderr)
        return 2  # D-06 hard refuse — NOTHING written, reports/ untouched.
    except CompletionHonestyViolation as e:
        print(
            format_completion_honesty_diagnostic(e.hits, e.buffer_name),
            file=sys.stderr,
        )
        return 3  # D-32 hard refuse.

    # ----- Single write chokepoint (only reached when both buffers pass). -----
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown_buf, encoding="utf-8")
    json_path.write_text(json_buf, encoding="utf-8")
    return 0
