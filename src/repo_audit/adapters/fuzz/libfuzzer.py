"""libFuzzer crash-output PARSE (atheris / jazzer common). FACT + LOCATION ONLY.

Native fuzzers built on libFuzzer (atheris for Python, jazzer for the JVM) print
a recognizable crash report to STDERR and write the offending input to a
``crash-<sha1>`` (atheris) / ``Crash-<sha1>.java`` (jazzer) artifact file on disk.

T-16-03-01 (Information Disclosure) — the crash-artifact bytes are ATTACKER-
INFLUENCED input. This parser reads ONLY the stderr text: it extracts the crash
ARTIFACT FILENAME and a LOCATION HINT (the top failing frame). It NEVER opens,
reads, or surfaces the ``crash-<sha1>`` artifact bytes. The Finding schema has no
``value`` / ``raw`` field (SCH-08, structurally enforced), so the byte literally
has no field to land in — this parser enforces that contract by construction.

A :class:`CrashSummary` carries exactly ``(engine, crash_filename, location_hint)``
— never bytes. Each becomes one counterexample Finding at ``severity='major'``,
``evidence_type='static'``, ``confidence='candidate'`` (SCH-04: candidate caps
below critical), naming the fact + location only.

This is a PURE TRANSFORM: it consumes already-captured stderr text, never shells
out, never touches the filesystem, and never raises.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "fuzz"
_DIMENSION = "test_integrity"

FuzzEngine = Literal["atheris", "jazzer"]

# The artifact line libFuzzer prints, e.g.:
#   Test unit written to ./crash-0a1b2c3d...
#   artifact_prefix='./'; Test unit written to ./crash-<sha1>
# jazzer writes Crash-<sha1>.java. Capture the bare filename only (never read it).
_CRASH_FILE = re.compile(
    r"(?:Test unit written to|written to)\s+\S*?"
    r"(?P<fname>(?:crash|Crash)-[0-9A-Za-z]+(?:\.java)?)",
)
# Fallback: any standalone crash-<sha1> / Crash-<sha1>.java token in the stderr.
_CRASH_TOKEN = re.compile(r"\b(?P<fname>(?:crash|Crash)-[0-9A-Za-z]+(?:\.java)?)\b")

# The top failing frame, e.g.:  "#0 in parse_header /repo/fuzz/fuzz_parser.py:42"
_FRAME_LOC = re.compile(
    r"#0\s+(?:in\s+)?(?P<fn>\S+)\s+(?P<loc>\S+:\d+)"
)
# jazzer-style stack frame:  "at com.example.Parser.parse(Parser.java:42)"
_JVM_FRAME = re.compile(r"\bat\s+(?P<sym>[\w.$]+)\((?P<loc>[\w.$]+:\d+)\)")


@dataclass(frozen=True)
class CrashSummary:
    """A single counterexample — FACT + LOCATION only, NEVER the crash bytes."""

    engine: str
    crash_filename: str
    location_hint: str


def _infer_engine(stderr: str) -> str:
    """Best-effort engine inference from the stderr text (informational only)."""
    low = stderr.lower()
    if "jazzer" in low or "Crash-" in stderr or ".java)" in stderr:
        return "jazzer"
    return "atheris"


def parse_libfuzzer_crashes(stderr: str, repo_path=None) -> list[CrashSummary]:
    """Parse libFuzzer crash stderr into ``CrashSummary`` facts. NEVER reads bytes.

    Extracts each crash ARTIFACT FILENAME + a LOCATION HINT from the recorded
    stderr text. The ``crash-<sha1>`` artifact file itself is NEVER opened
    (T-16-03-01) — ``repo_path`` is accepted only to mirror the call shape and is
    deliberately unused for any byte read. Returns one :class:`CrashSummary` per
    crash file named in the stderr. Never raises.

    Args:
        stderr: the captured libFuzzer (atheris/jazzer) stderr text.
        repo_path: accepted for call-shape symmetry; INTENTIONALLY UNUSED — the
            crash artifact bytes are never read.

    Returns:
        A list of :class:`CrashSummary` (engine, crash_filename, location_hint).
    """
    del repo_path  # explicitly never read the crash artifact (T-16-03-01)
    if not stderr:
        return []

    engine = _infer_engine(stderr)
    location = _extract_location(stderr)

    summaries: list[CrashSummary] = []
    seen: set[str] = set()
    # Prefer the explicit "written to" line; fall back to any crash token.
    matches = list(_CRASH_FILE.finditer(stderr)) or list(_CRASH_TOKEN.finditer(stderr))
    for m in matches:
        fname = m.group("fname")
        if fname in seen:
            continue
        seen.add(fname)
        summaries.append(
            CrashSummary(
                engine=engine,
                crash_filename=fname,
                location_hint=location,
            )
        )
    return summaries


def _extract_location(stderr: str) -> str:
    """Extract the top failing-frame location hint; "" when none is parseable."""
    m = _FRAME_LOC.search(stderr)
    if m:
        return f"{m.group('fn')} @ {m.group('loc')}"
    j = _JVM_FRAME.search(stderr)
    if j:
        return f"{j.group('sym')} @ {j.group('loc')}"
    return ""


def build_crash_findings(summaries: list[CrashSummary]) -> list[Finding]:
    """Build one counterexample Finding per crash (FACT + LOCATION, no bytes).

    ``severity='major'``, ``evidence_type='static'``, ``confidence='candidate'``
    (SCH-04 caps candidate below critical). The recommendation names the crash
    FILE + LOCATION only — never the input bytes (T-16-03-01). Never raises.
    """
    findings: list[Finding] = []
    for s in summaries:
        loc = s.location_hint or "location not parseable from stderr"
        findings.append(
            Finding(
                dimension=_DIMENSION,
                severity="major",  # SCH-04: candidate caps below critical
                evidence_type="static",
                confidence="candidate",
                source_tool=_SOURCE_TOOL,
                source_collector="fuzz_native",
                rule_id="fuzz_counterexample",
                recommendation=(
                    f"{s.engine} fuzzing surfaced a crash ({s.crash_filename}) "
                    f"at {loc}. A counterexample exists — reproduce it from the "
                    "fuzzer's saved artifact in your own environment. (The raw "
                    "crash input is never surfaced here, only the fact + location.)"
                ),
                evidence=Evidence(
                    tool=f"{s.engine}-libfuzzer",
                    output_snippet=(
                        f"crash artifact: {s.crash_filename}; location: {loc} "
                        "(raw input bytes intentionally omitted)"
                    ),
                    parsed_value={
                        "engine": s.engine,
                        "crash_filename": s.crash_filename,
                        "location_hint": s.location_hint,
                    },
                ),
            )
        )
    return findings


__all__ = [
    "CrashSummary",
    "FuzzEngine",
    "parse_libfuzzer_crashes",
    "build_crash_findings",
]
