"""Render a ScanReport into markdown + JSON sidecar.

Two entry points:
    render_markdown(scan_report) -> str
        Pure function: produces the markdown buffer. No I/O.

    render_and_write(scan_report, md_path, json_path) -> int
        Build both buffers, auto-create md_path.parent (D-15), write both.
        Returns 0 on success, non-zero on failure.

Plan 05 interposes the secret-lint chokepoint INSIDE render_and_write
between buffer-build and disk-write. The function signature is stable.

The write step is encapsulated in `_write_outputs(markdown_buf, json_buf,
md_path, json_path)` so Plan 05 can drop `lint_buffer(...)` calls between
buffer-build and that single chokepoint -- no scattered `Path.write_text`
calls to track down.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from repo_audit.render.filters import (
    evidence_verb,
    provenance,
    severity_emoji,
)
from repo_audit.schema.report import ScanReport


def _make_env() -> Environment:
    """Build the Jinja2 environment with our filters and loader.

    autoescape=False -- we emit markdown, not HTML.
    StrictUndefined -- typos like `{{ report.met.x }}` raise at render time
    rather than silently emit empty strings. Caught by the golden-render test.
    """
    env = Environment(
        loader=PackageLoader("repo_audit", "render/templates"),
        autoescape=False,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["severity_emoji"] = severity_emoji
    env.filters["provenance"] = provenance
    env.filters["evidence_verb"] = evidence_verb
    return env


def render_markdown(scan_report: ScanReport) -> str:
    """Render the markdown buffer. Pure; no I/O."""
    env = _make_env()
    template = env.get_template("state_report.md.j2")
    return template.render(report=scan_report)


def _write_outputs(
    markdown_buf: str,
    json_buf: str,
    md_path: Path,
    json_path: Path,
) -> None:
    """The single disk-write chokepoint.

    D-15: auto-create md_path.parent here -- AFTER buffers are built and
    (in Plan 05+) AFTER secret-lint passes. If secret-lint fires earlier,
    this helper is never called and the target repo remains untouched
    (no orphan `docs/state-reports/` directory left behind -- Pitfall 8).

    Plan 05 will guard the call site of this helper with `lint_buffer(...)`
    on both buffers; this function's body stays unchanged.
    """
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown_buf, encoding="utf-8")
    json_path.write_text(json_buf, encoding="utf-8")


def render_and_write(
    scan_report: ScanReport,
    md_path: Path,
    json_path: Path,
) -> int:
    """Build markdown + JSON buffers, write both. Returns 0 on success.

    Plan 05 will interpose secret-lint between buffer-build and the
    `_write_outputs` call below by replacing the body between
    "1. Build buffers" and "2. Write" with `lint_buffer(...)` calls.
    The function signature here is stable.

    D-15: directory auto-create is inside `_write_outputs`. A render
    failure leaves the target repo untouched; a secret-lint failure
    (Plan 05) leaves it untouched too.
    """
    # 1. Build both buffers in memory.
    markdown_buf = render_markdown(scan_report)
    json_buf = scan_report.model_dump_json(indent=2)

    # 2. (Plan 05 will interpose `lint_buffer(markdown_buf)`
    #     and `lint_buffer(json_buf)` here.)

    # 3. Single disk-write chokepoint.
    _write_outputs(markdown_buf, json_buf, md_path, json_path)
    return 0
