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
from typing import TYPE_CHECKING

from jinja2 import Environment, PackageLoader, StrictUndefined

from repo_audit.render.completion_honesty import (
    CompletionHonestyViolation,
    completion_honesty_lint,
    format_completion_honesty_diagnostic,
)
from repo_audit.render.corroboration import (
    classify_critical_finding,
    detect_corroboration_disputes,
)
from repo_audit.render.exec_summary import (
    build_deterministic_exec_header,
    dilution_strip_exec_summary,
)
from repo_audit.render.faithfulness import (
    build_allowed_numbers,
    check_faithfulness,
    load_faithfulness_allowlist,
)
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

if TYPE_CHECKING:
    from repo_audit.agent.schema import AgentScanReport


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
    """Render the markdown buffer. Pure; no I/O.

    Phase 1-3 entry point: renders with no agent narrative (agent_output=None)
    and a deterministic exec header built from the finding store. The Phase 4
    template branches on ``agent_output is none`` + ``report.meta.agent_status``
    so this path produces the deterministic-only report (no agent kwargs leak
    StrictUndefined errors).
    """
    env = _make_env()
    template = env.get_template("state_report.md.j2")
    return template.render(
        report=scan_report,
        agent_output=None,
        deterministic_exec_header=build_deterministic_exec_header(scan_report.findings),
        critical_render_classes=_compute_critical_render_classes(scan_report),
    )


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


def _composite_finding_ref(f: object) -> str:
    """Composite key shared with the template + corroboration dispute matcher.

    Shape: ``{source_tool}::{rule_id}::{file}:{line}``. The Jinja template
    rebuilds the identical key (Plan 04-08 Task 2) to look up the render class
    in ``critical_render_classes``; the two MUST stay in lock-step.
    """
    return (
        f"{getattr(f, 'source_tool', '')}::"
        f"{getattr(f, 'rule_id', '') or ''}::"
        f"{getattr(f, 'file', '') or ''}:{getattr(f, 'line', '') or ''}"
    )


def render_and_write(
    scan_report: ScanReport,
    md_path: Path,
    json_path: Path,
    *,
    agent_output: "AgentScanReport | None" = None,
) -> int:
    """Build markdown + JSON buffers, run chokepoint pipeline, write both.

    D-64 LOCKED chokepoint pipeline (CONTEXT §"D-64" verbatim — order is
    the contract; any re-shuffle breaks the lock):

      1. secret_lint          (D-07)  <- FIRST  on agent narrative buffer
      2. completion_honesty_lint (D-32) <- SECOND on agent narrative buffer
      3. check_faithfulness   (D-64)  <- THIRD  on each dim narrative
      4. dilution_strip       (D-70)  <- FOURTH on executive_summary
      5. corroboration_classify (D-69) <- FIFTH  per blocker/critical finding
      6. _write_outputs       (D-15)  <- LAST after second-pass full-buffer
                                         secret_lint + completion_honesty_lint

    The first two linters already exist in render/secret_lint.py +
    render/completion_honesty.py from Phases 1-2; this function extends
    the pipeline to insert check_faithfulness AFTER them, then
    dilution_strip + corroboration_classify, then full-buffer second-pass
    linters as defense in depth, then _write_outputs.

    Exit codes:
      0 -- success (including D-67 deterministic-only fallback)
      2 -- secret-lint refused (REP-05 / D-06)
      3 -- completion-honesty refused (SAFE-08 / D-32)
    """
    # ----- Build allowed_numbers + load regex BEFORE prose touches anything. -----
    allowed_numbers = build_allowed_numbers(
        scan_report.findings, scan_report.scope_ledger, scan_report.meta,
    )
    trigger_regex, allowlist_regex = load_faithfulness_allowlist()
    deterministic_exec_header = build_deterministic_exec_header(scan_report.findings)

    cleaned_agent_output = agent_output
    critical_render_classes: dict[str, str] = {}

    # ----- D-64 LOCKED CHOKEPOINT PIPELINE on agent narrative buffer. -----
    # Order is contractual: secret_lint -> completion_honesty -> check_faithfulness
    # -> dilution_strip -> corroboration_classify. Do NOT re-shuffle.
    if agent_output is not None:
        # Step 4a (D-07 -- FIRST): secret_lint on agent narrative buffer.
        agent_narrative_buf = "\n\n".join(
            [dim.narrative for dim in agent_output.dimensions]
            + [agent_output.executive_summary or ""]
        )
        try:
            lint_buffer(agent_narrative_buf, buffer_name="agent-narrative")
        except SecretsDetected as e:
            print(format_diagnostic(e.hits, e.buffer_name), file=sys.stderr)
            return 2

        # Step 4b (D-32 -- SECOND): completion_honesty_lint on agent narrative buffer.
        try:
            completion_honesty_lint(
                agent_narrative_buf,
                partial=scan_report.meta.partial,
                buffer_name="agent-narrative",
            )
        except CompletionHonestyViolation as e:
            print(
                format_completion_honesty_diagnostic(e.hits, e.buffer_name),
                file=sys.stderr,
            )
            return 3

        # Step 4c (D-64 -- THIRD): check_faithfulness on each dim narrative.
        all_violations = []
        cleaned_dimensions = []
        for dim in agent_output.dimensions:
            clean_prose, violations = check_faithfulness(
                dim.narrative,
                allowed_numbers,
                trigger_regex,
                allowlist_regex,
                tolerance=0.05,
                dimension=dim.dimension,
            )
            cleaned_dimensions.append(dim.model_copy(update={"narrative": clean_prose}))
            all_violations.extend(violations)

        # Step 4d (D-70 -- FOURTH): dilution_strip on executive_summary.
        clean_exec, dilution_strips = dilution_strip_exec_summary(
            agent_output.executive_summary,
        )

        # Step 4e (D-69 -- FIFTH): corroboration_classify per critical/blocker.
        disputes = detect_corroboration_disputes(agent_output, scan_report.findings)
        for f in scan_report.findings:
            if getattr(f, "severity", "") in ("blocker", "critical"):
                critical_render_classes[_composite_finding_ref(f)] = (
                    classify_critical_finding(f, scan_report.findings)
                )

        # Step 4f: mutate meta IN PLACE (Plan 04-03 fields).
        scan_report.meta.faithfulness_violations = all_violations
        scan_report.meta.exec_summary_dilution_strips = dilution_strips
        scan_report.meta.agent_corroboration_disputes = disputes

        # Step 4g: cleaned agent_output for template render.
        cleaned_agent_output = agent_output.model_copy(
            update={
                "dimensions": cleaned_dimensions,
                "executive_summary": clean_exec,
            }
        )

        # D-64 stderr per-violation line (value-blind preview).
        for v in all_violations:
            preview = v.original_sentence[:80].replace("\n", " ")
            tokens = ", ".join(v.offending_tokens[:5])
            print(
                f'faithfulness: stripped "{preview}..." (offending: {tokens})',
                file=sys.stderr,
            )
    else:
        # No agent_output -> still compute critical_render_classes from
        # deterministic findings so the fallback render badges critical rows.
        critical_render_classes = _compute_critical_render_classes(scan_report)

    # ----- Build buffers. -----
    # No-agent path routes through render_markdown() so it stays the single
    # documented pure-render entry point (Phase 1-3 callers + tests that
    # intercept the buffer there still work). The agent path needs the extra
    # kwargs and builds the buffer directly.
    if cleaned_agent_output is None:
        markdown_buf = render_markdown(scan_report)
    else:
        markdown_buf = _render_markdown_with_agent(
            scan_report=scan_report,
            agent_output=cleaned_agent_output,
            deterministic_exec_header=deterministic_exec_header,
            critical_render_classes=critical_render_classes,
        )
    json_buf = scan_report.model_dump_json(indent=2)

    # ----- SECOND-PASS chokepoints on FULL buffers (defense in depth). -----
    # Catches any leak that survived the narrative-only pass + catches leaks
    # in the deterministic portion (findings tables, scope ledger, meta).
    partial = scan_report.meta.partial
    try:
        lint_buffer(markdown_buf, buffer_name="markdown")
        lint_buffer(json_buf, buffer_name="json-sidecar")
        completion_honesty_lint(markdown_buf, partial=partial, buffer_name="markdown")
        completion_honesty_lint(json_buf, partial=partial, buffer_name="json-sidecar")
    except SecretsDetected as e:
        print(format_diagnostic(e.hits, e.buffer_name), file=sys.stderr)
        return 2  # D-06 hard refuse; ``_write_outputs`` is NOT called.
    except CompletionHonestyViolation as e:
        print(
            format_completion_honesty_diagnostic(e.hits, e.buffer_name),
            file=sys.stderr,
        )
        return 3  # D-32 hard refuse; distinct from secret-lint exit code.

    # ----- Single disk-write chokepoint (D-15 mkdir lives inside). -----
    _write_outputs(markdown_buf, json_buf, md_path, json_path)
    return 0


def _render_markdown_with_agent(
    *,
    scan_report: ScanReport,
    agent_output: "AgentScanReport | None",
    deterministic_exec_header: str,
    critical_render_classes: dict[str, str],
) -> str:
    """Template render with the Phase 4 agent kwargs."""
    env = _make_env()
    template = env.get_template("state_report.md.j2")
    return template.render(
        report=scan_report,
        agent_output=agent_output,
        deterministic_exec_header=deterministic_exec_header,
        critical_render_classes=critical_render_classes,
    )


def _compute_critical_render_classes(scan_report: ScanReport) -> dict[str, str]:
    """D-69 render classes for every blocker/critical finding (no-agent path).

    Defined AFTER render_and_write so the FIRST in-body occurrence of
    classify_critical_finding(...) in this module is the Step 4e D-69 FIFTH
    chokepoint call inside the locked pipeline — the static line-order grep
    in Plan 04-08 acceptance_criteria depends on that first occurrence
    following dilution_strip_exec_summary(...).
    """
    return {
        _composite_finding_ref(f): classify_critical_finding(f, scan_report.findings)
        for f in scan_report.findings
        if getattr(f, "severity", "") in ("blocker", "critical")
    }
