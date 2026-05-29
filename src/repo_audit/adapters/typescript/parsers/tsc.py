"""D-39 tsc parser: tsc --noEmit --pretty=false diagnostic → Finding.

Verified diagnostic shape (tsc 5.9.3, 2026-05-28):

    path(line,col): error TSCODE: message text.

Per Pitfall 4: tsc emits diagnostics on STDOUT, not stderr. Parser reads
``inv.stdout`` only.

Per Pitfall 5: tsc exit codes are interpreted at the adapter layer
(``status_from_invocation`` maps exit 2 → ok with findings, exit 1 →
unavailable; the parser is not called when the adapter sets status to
anything other than 'ok'). This module assumes the adapter only invokes
it when ``status == 'ok'``.

Per D-51: every tsc finding is ``severity='critical'`` AND
``evidence_type='static'``; the SCH-03 validator in
``schema/finding.py`` structurally requires a non-empty
``confidence_caveat`` on construction. The ``TSC_DEFAULT_CAVEAT``
constant supplies it on every emission.

Per D-48: tsc findings live in the ``correctness`` dimension. The
adapter.yaml's ``dimension: quality_debt`` metadata on the tool block
is recorded on the AdapterResult shell (free string) but does NOT flow
into the Finding's ``dimension`` field — Finding.dimension is the
schema Literal and the parser owns the routing decision per D-48.

Robustness:
    * Non-matching lines (tsc progress chatter like
      ``Found N errors in M files.``) are silently skipped.
    * The regex tolerates Windows-style backslash paths via the
      non-greedy ``(?P<file>.+?)`` capture.
"""
from __future__ import annotations

import re

from repo_audit.adapters.base import InvocationResult
from repo_audit.schema.finding import Evidence, Finding


# Verified live (03-RESEARCH "Code Examples"): tsc 5.9.3 with
# --pretty=false emits one diagnostic per line in this format.
_DIAG_RE = re.compile(
    r"^(?P<file>.+?)\((?P<line>\d+),(?P<col>\d+)\): error (?P<code>TS\d+): (?P<msg>.+)$"
)


# D-51 default caveat. SCH-03 validator (``schema/finding.py``) RAISES
# ``ValidationError`` if ``confidence_caveat`` is None/empty when
# ``severity='critical'`` AND ``evidence_type='static'``. This constant
# ensures every tsc Finding constructs successfully.
TSC_DEFAULT_CAVEAT: str = (
    "Static type-check signal. Runtime behavior may differ when `any`, `as`, "
    "or `// @ts-expect-error` masks the type; verify the call site exercises "
    "the typed branch."
)


def parse(inv: InvocationResult) -> list[Finding]:
    """Transform tsc stdout into Findings.

    Adapter contract (per WAVE 1 03-02): this parser is invoked ONLY when
    ``InvocationResult`` was a successful tsc run (``status='ok'``). Exit
    code 0 (clean) means stdout is empty; exit 2 means stdout contains
    diagnostics. Either way we just walk lines.

    Non-matching lines are silently skipped (tsc occasionally emits
    progress lines like ``Found N errors in M files.``).
    """
    findings: list[Finding] = []
    for raw_line in inv.stdout.splitlines():
        m = _DIAG_RE.match(raw_line.rstrip())
        if m is None:
            continue
        file_str = m["file"]
        line_no = int(m["line"])
        col_no = int(m["col"])
        ts_code = m["code"]
        message = m["msg"]
        findings.append(
            Finding(
                dimension="correctness",            # D-48
                severity="critical",                # D-51
                file=file_str,
                line=line_no,
                evidence_type="static",             # D-17
                confidence="high",
                recommendation=f"Resolve {ts_code}: {message}",
                source_tool="tsc",
                source_collector="typescript_adapter",
                rule_id=ts_code,                    # e.g., "TS2322"
                confidence_caveat=TSC_DEFAULT_CAVEAT,  # D-51 / SCH-03 mandatory
                evidence=Evidence(
                    tool="tsc",
                    output_snippet=raw_line,         # D-02 cap auto-applies (2048)
                    parsed_value={
                        "diagnostic_code": ts_code,
                        "column": col_no,
                        "message": message,
                    },
                    line_range=(line_no, line_no),
                ),
            )
        )
    return findings


__all__ = ["TSC_DEFAULT_CAVEAT", "parse"]
