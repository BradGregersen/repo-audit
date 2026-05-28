"""Render a ScanReport into markdown + JSON sidecar.

Two entry points:
    render_markdown(scan_report) -> str
        Pure function: produces the markdown buffer. No I/O.

    render_and_write(scan_report, md_path, json_path) -> int
        Build both buffers, lint both (Plan 01-05 D-07 chokepoint),
        auto-create md_path.parent (D-15), write both. Returns 0 on
        success, ``2`` if the secret-lint refuses the write (D-06).

The write step is encapsulated in ``_write_outputs(markdown_buf, json_buf,
md_path, json_path)`` so the secret-lint chokepoint sits cleanly between
buffer-build and the single ``_write_outputs`` call -- no scattered
``Path.write_text`` sites to audit (Pitfall 2 mitigation).

D-07 ordering invariant (load-bearing):
    1. Build BOTH buffers in memory.
    2. Lint BOTH (markdown first, then JSON sidecar).
    3. Only if both pass: ``_write_outputs(...)`` (which mkdirs the
       parent and writes the two files).

On secret-lint failure (``SecretsDetected``):
    - Emit the value-blind diagnostic to stderr.
    - Return ``2`` (non-zero per D-06).
    - DO NOT mkdir, DO NOT write -- the target repo stays untouched
      (Pitfall 8).
"""
from __future__ import annotations

import sys
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from repo_audit.render.filters import (
    evidence_verb,
    provenance,
    severity_emoji,
)
from repo_audit.render.secret_lint import (
    SecretsDetected,
    format_diagnostic,
    lint_buffer,
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
    """Build markdown + JSON buffers, lint both, write both. Returns 0 on success.

    D-07 ordering (critical, load-bearing):
        1. Build BOTH buffers in memory.
        2. Secret-lint BOTH (markdown first, then JSON).
        3. Only if both pass: ``_write_outputs(...)`` (the single
           disk-write chokepoint, which mkdirs and writes).

    If secret-lint fires (``SecretsDetected``):
        - Print the value-blind diagnostic to stderr (D-06).
        - Return ``2`` (non-zero per D-06).
        - DO NOT mkdir, DO NOT write -- the target repo stays untouched
          (Pitfall 8 mitigation).

    Returns:
        0 -- both buffers clean and written successfully.
        2 -- secret-lint refused; nothing written, stderr diagnostic emitted.
    """
    # 1. Build both buffers in memory.
    markdown_buf = render_markdown(scan_report)
    json_buf = scan_report.model_dump_json(indent=2)

    # 2. D-07 chokepoint: lint BOTH before either touches disk.
    try:
        lint_buffer(markdown_buf, buffer_name="markdown")
        lint_buffer(json_buf, buffer_name="json-sidecar")
    except SecretsDetected as e:
        print(format_diagnostic(e.hits, e.buffer_name), file=sys.stderr)
        return 2  # D-06 hard refuse; ``_write_outputs`` is NOT called.

    # 3. Single disk-write chokepoint (D-15 mkdir lives inside).
    _write_outputs(markdown_buf, json_buf, md_path, json_path)
    return 0
