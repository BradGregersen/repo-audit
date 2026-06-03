"""Secret-lint chokepoint for the renderer (REP-05, D-05..D-08).

The single chokepoint per D-07: both the markdown AND the JSON sidecar buffers
are scanned in-memory BEFORE either reaches disk. On any hit, neither file is
written and a value-blind diagnostic goes to stderr.

Detection sources (D-05):
    1. gitleaks (named-rule precision): AWS keys, GitHub PATs, Stripe, etc.
       Invoked via subprocess; graceful degrade when not on PATH.
    2. Known-pattern backstop (pure-Python named rules): a small set of
       high-confidence prefix patterns (AWS ``AKIA``, GitHub ``ghp_``,
       Stripe ``sk_live_``, Google ``AIza`` ...) so that the canonical
       AWS-example fixture and other low-entropy structured secrets still
       refuse when gitleaks is not installed. Added as a Rule-2 defense-in-
       depth during Plan 01-05 -- see SUMMARY for rationale.
    3. Shannon entropy backstop: tokens >=5 chars with entropy >=4.5
       bits/char. Pure Python; always runs.

Output discipline (D-06):
    - Diagnostic format: ``<buffer_name>:<line> <rule_id> [REDACTED:<len>]``
    - The raw secret value is NEVER stored on SecretHit (only its length).
    - The diagnostic NEVER contains the original entropy-flagged token.
"""
from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# D-05: detection thresholds
ENTROPY_THRESHOLD_BITS_PER_CHAR: float = 4.5
TOKEN_MIN_LEN: int = 5

# Tokenizer for entropy scan -- matches identifier-like and base64-like strings.
TOKENIZER = re.compile(r"[A-Za-z0-9_\-+/=]{5,}")

# Subprocess timeout for gitleaks invocation (defense against hung child).
GITLEAKS_TIMEOUT_S: int = 30

# Known-pattern backstop (D-05 named-rule precision, gitleaks-absent path).
# Each entry: (rule_id, compiled regex). Keep this list intentionally small --
# defense in depth, not a gitleaks replacement. Patterns mirror the prefixes
# gitleaks 8.x catches with its default rule set for the highest-incidence
# secret formats. Anchored to the BEGINNING of the matched token by use of
# explicit prefix literals so the regex itself encodes the structural shape.
#
# Why this exists (added Plan 01-05 as a Rule-2 defense-in-depth):
#   The canonical AWS access-key documentation fixture used by
#   tests/conftest.py::synthetic_secret has only ~3.68 bits/char of Shannon
#   entropy (many repeated letters). Below the 4.5 threshold the entropy
#   backstop ignores it. In a no-gitleaks environment the renderer would
#   silently leak. The known-pattern scan closes this gap for the
#   highest-incidence prefixes without compromising D-05's locked entropy
#   threshold.
KNOWN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS Access Key ID: AKIA + 16 alnum chars (uppercase + digits)
    ("aws-access-key-id", re.compile(r"AKIA[A-Z0-9]{16}")),
    # AWS Secret Access Key style temporary tokens: ASIA + 16
    ("aws-temporary-access-key", re.compile(r"ASIA[A-Z0-9]{16}")),
    # GitHub Personal Access Tokens (classic + fine-grained)
    ("github-pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    # Stripe live secret key
    ("stripe-secret-key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    # Google API key
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    # Slack tokens
    ("slack-token", re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}")),
    # Anthropic API key
    ("anthropic-api-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    # OpenAI API key
    ("openai-api-key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
]


@dataclass(frozen=True)
class SecretHit:
    """A single secret-lint hit.

    NOTE: There is NO ``value``/``secret``/``raw``/``match`` field on this
    dataclass. We store only the line, rule_id, and the LENGTH of the matched
    token. Compare to schema/finding.py SCH-08 -- same principle.
    """

    line: int
    rule_id: str  # gitleaks rule id, or "entropy-backstop"
    redacted_len: int
    # Per-scanner attribution (Phase 12 Pitfall 4 fix). Set EXPLICITLY by the
    # producing scanner -- there is intentionally NO default, so a missing
    # attribution is a construction error rather than a silent "" that lets an
    # entropy-backstop hit masquerade as a gitleaks hit. Producers:
    #   scan_with_gitleaks / scan_working_tree -> "gitleaks"
    #   scan_git_history                        -> "gitleaks-history"
    #   scan_with_known_patterns / entropy      -> "in-process"
    source: str
    # Optional repo-relative file path, populated only by the gitleaks
    # target-path modes (``scan_working_tree`` / ``scan_git_history``) whose JSON
    # reports a ``File`` field. The stdin/in-process scanners operate on a single
    # buffer with no file context and leave this ``None``. NOTE: a file PATH is
    # not a secret value, so carrying it does not violate the value-blind
    # contract (still NO value/secret/raw/match field).
    file: str | None = None


class SecretsDetected(Exception):
    """Raised by the render pipeline when secret-lint fires. Aborts write."""

    def __init__(self, hits: list[SecretHit], buffer_name: str) -> None:
        self.hits = list(hits)
        self.buffer_name = buffer_name
        super().__init__(
            f"Secrets detected in {buffer_name} buffer: {len(hits)} hit(s)"
        )


def shannon_entropy_bits_per_char(s: str) -> float:
    """Standard Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def scan_with_entropy(text: str) -> list[SecretHit]:
    """D-05 in-process backstop. Always runs. Returns hits with line numbers.

    This is the "no-subprocess" detection bundle that runs whether or not
    gitleaks is on PATH. It combines two pure-Python checks:

        1. Shannon entropy on tokens >= ``TOKEN_MIN_LEN`` chars: threshold
           ``ENTROPY_THRESHOLD_BITS_PER_CHAR`` (D-05).
        2. Known-pattern named-rule scan via ``scan_with_known_patterns``
           (defense-in-depth, added Plan 01-05).

    The function name "entropy" is retained for backwards compatibility with
    the plan's exported contract and the test imports; the body is the full
    in-process backstop because the canonical AWS-example fixture has
    sub-threshold Shannon entropy (~3.68 bits/char) yet a high-confidence
    structural shape that the known-pattern table catches. See the module
    docstring for the rationale.
    """
    hits: list[SecretHit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for m in TOKENIZER.finditer(line):
            token = m.group(0)
            if len(token) < TOKEN_MIN_LEN:
                continue
            if shannon_entropy_bits_per_char(token) >= ENTROPY_THRESHOLD_BITS_PER_CHAR:
                hits.append(
                    SecretHit(
                        line=lineno,
                        rule_id="entropy-backstop",
                        redacted_len=len(token),
                        source="in-process",
                    )
                )
    # Compose with the known-pattern table so the in-process backstop catches
    # structured secrets whose Shannon entropy alone falls below threshold.
    hits.extend(scan_with_known_patterns(text))
    return hits


def scan_with_known_patterns(text: str) -> list[SecretHit]:
    """D-05 named-rule precision scan against the small in-process pattern table.

    Runs alongside the entropy backstop (always available, no subprocess) so
    that structured secrets with low Shannon entropy -- AWS keys whose
    canonical example mixes only a small alphabet -- still refuse to ship.
    See ``KNOWN_PATTERNS`` for the rule set.

    Returns hits with line numbers (1-indexed) and ORIGINAL token length
    derived from the regex match span. The matched value is NEVER stored
    on the returned ``SecretHit``.
    """
    hits: list[SecretHit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule_id, pattern in KNOWN_PATTERNS:
            for m in pattern.finditer(line):
                hits.append(
                    SecretHit(
                        line=lineno,
                        rule_id=rule_id,
                        redacted_len=m.end() - m.start(),
                        source="in-process",
                    )
                )
    return hits


def scan_with_gitleaks(
    text: str, *, timeout: float = GITLEAKS_TIMEOUT_S
) -> list[SecretHit]:
    """D-05 gitleaks named-rule scan via subprocess.

    Returns ``[]`` when gitleaks is not on PATH (graceful degrade per
    Assumption A1 in 01-RESEARCH.md and the Environment Availability table).
    The ``repo-audit --doctor`` in Phase 7 will surface gitleaks-absent as a
    degraded-mode warning.

    Per CLAUDE.md hard rule: ``shell=False``, command as ``list[str]``,
    explicit ``timeout``.

    05.1-gap: ``timeout`` (default ``GITLEAKS_TIMEOUT_S`` = 30 s — UNCHANGED for
    the renderer chokepoint's existing callers) lets the secret_detection
    collector cap the PER-FILE subprocess at the scan budget remaining, so a
    gitleaks call started near the scan deadline cannot overshoot it by a full
    30 s. A non-positive ``timeout`` skips the call (returns ``[]``) rather than
    launching a doomed subprocess.

    ``redacted_len`` is derived from gitleaks's ``EndColumn - StartColumn``
    JSON fields -- i.e., the position-derived ORIGINAL token length on the
    matched line -- NOT from the ``Secret`` field (which, with ``--redact``,
    holds a fixed-length placeholder like ``"REDACTED"`` and would erase the
    real length signal). D-06 requires the diagnostic to expose the true
    length so the user can distinguish a 40-char AWS key from a 5-char Slack
    token. We only fall back to ``len(Secret)`` if both column fields are
    absent or zero (defensive).
    """
    if shutil.which("gitleaks") is None:
        return []
    if timeout <= 0:
        return []

    # Gitleaks 8.x supports ``gitleaks stdin`` for piped input. Flags verified
    # at implementation time per Assumption A1 in 01-RESEARCH.md.
    try:
        result = subprocess.run(
            [
                "gitleaks",
                "stdin",
                "--report-format",
                "json",
                "--redact",
                "--no-banner",
            ],
            input=text,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # CLAUDE.md hard rule
            check=False,  # gitleaks exits non-zero when it finds secrets
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    # Parse JSON output via the shared value-blind helper (source="gitleaks").
    return _parse_gitleaks_json(result.stdout or "", source="gitleaks")


def _parse_gitleaks_json(stdout: str, *, source: str) -> list[SecretHit]:
    """Parse gitleaks JSON output into value-blind ``SecretHit``s.

    The ONE place gitleaks JSON becomes ``SecretHit``s -- shared verbatim by
    ``scan_with_gitleaks`` (stdin mode), ``scan_working_tree`` (``gitleaks dir``)
    and ``scan_git_history`` (``gitleaks git`` full-history mode) so the
    column-derived ``redacted_len`` discipline is implemented exactly once.

    ``redacted_len`` is derived from gitleaks's ``EndColumn - StartColumn`` JSON
    fields -- i.e. the position-derived ORIGINAL token length on the matched
    line -- NOT from the ``Secret`` field. With ``--redact`` gitleaks overwrites
    ``Secret`` with a fixed placeholder (e.g. ``"REDACTED"`` = 8 chars), so
    ``len(Secret)`` would lie about the true length. D-06 requires the diagnostic
    to expose the real length so the user can tell a 40-char AWS key from a
    5-char Slack token. We ONLY fall back to ``len(Secret)`` when both column
    fields are absent or zero (defensive); the raw value is otherwise never read.

    Args:
        stdout: raw gitleaks JSON (a JSON array of finding dicts).
        source: the per-scanner attribution stamped onto every returned
            ``SecretHit.source`` (e.g. ``"gitleaks"`` or ``"gitleaks-history"``).

    Returns:
        A list of value-blind ``SecretHit``s; ``[]`` on empty/non-array/invalid
        JSON.
    """
    stdout = (stdout or "").strip()
    if not stdout:
        return []
    try:
        findings = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(findings, list):
        return []

    hits: list[SecretHit] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        start_col = int(f.get("StartColumn") or 0)
        end_col = int(f.get("EndColumn") or 0)
        col_span = end_col - start_col
        if col_span > 0:
            redacted_len = col_span
        else:
            # Defensive fallback when columns are absent/zero in the JSON. We
            # never want to handle the raw Secret value, but its placeholder
            # length is the only remaining signal in this degraded case.
            redacted_len = len(str(f.get("Secret") or ""))
        raw_file = f.get("File")
        hits.append(
            SecretHit(
                line=int(f.get("StartLine") or 0),
                rule_id=str(f.get("RuleID") or "gitleaks-unknown"),
                redacted_len=redacted_len,
                source=source,
                file=str(raw_file) if raw_file else None,
            )
        )
    return hits


def _run_gitleaks_target(
    subcommand: str,
    target: Path,
    *,
    timeout: float,
    source: str,
) -> list[SecretHit]:
    """Run gitleaks in a target-path mode (``git`` history or ``dir`` tree).

    INTENTIONAL subprocess discipline: this mirrors ``scan_with_gitleaks`` in
    THIS module, which calls ``subprocess.run`` directly with manual
    ``TimeoutExpired``/``FileNotFoundError`` handling. The ``secret_lint`` module
    owns its own value-blind subprocess wrapper by design (the ``run_tool`` seam
    is for the adapter layer); keeping these history/working-tree siblings
    consistent with ``scan_with_gitleaks`` is the correct pattern, NOT a defect
    to route through ``run_tool``.

    Per CLAUDE.md hard rule: ``shell=False``, command as ``list[str]``, explicit
    ``timeout``. Returns ``[]`` when gitleaks is absent (A1 graceful degrade) or
    on timeout / a non-positive budget. The JSON report is written to a tempfile
    and read back (A3 -- do NOT rely on ``/dev/stdout``).
    """
    if shutil.which("gitleaks") is None:
        return []
    if timeout <= 0:
        return []

    # gitleaks 8.30.1: ``gitleaks git <repo>`` walks FULL commit history;
    # ``gitleaks dir <path>`` scans a no-git working tree (Pitfall 2 — the
    # 8.18+ split of the legacy ``detect`` subcommand).
    # VERIFY: confirmed against `gitleaks git --help` on 8.30.1 — subcommand is
    # `git`; `--report-path` takes a file (use "-" for stdout). We write a
    # tempfile and read it back (A3) rather than relying on stdout buffering.
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "gitleaks-report.json"
        argv = [
            "gitleaks",
            subcommand,
            str(target),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--redact",  # never emit raw values (mirrors scan_with_gitleaks)
            "--no-banner",
        ]
        try:
            subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,  # CLAUDE.md hard rule
                check=False,  # gitleaks exits non-zero when it finds secrets
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        try:
            stdout = report_path.read_text(encoding="utf-8")
        except OSError:
            # gitleaks writes no report file when it finds nothing.
            return []
    return _parse_gitleaks_json(stdout, source=source)


def scan_git_history(repo_path: Path, *, timeout: float) -> list[SecretHit]:
    """HIST-01: gitleaks over a repo's FULL git history (committed-then-deleted
    secrets still count).

    Sibling of ``scan_with_gitleaks`` for the history-aware path. Runs
    ``gitleaks git <repo_path>`` once over all commits, parses the JSON report
    through the shared ``_parse_gitleaks_json`` helper, and stamps
    ``source="gitleaks-history"`` so the report can distinguish a history hit
    from a working-tree hit. Returns ``[]`` when gitleaks is not on PATH (the
    Wave-1 history collector maps absence to ``unavailable``) or on timeout.

    The value-blind contract is inherited verbatim from ``_parse_gitleaks_json``:
    ``--redact`` is passed and the raw ``Secret`` value is never stored on a
    returned ``SecretHit``.
    """
    return _run_gitleaks_target(
        "git", Path(repo_path), timeout=timeout, source="gitleaks-history"
    )


def scan_working_tree(repo_path: Path, *, timeout: float) -> list[SecretHit]:
    """COLL-03 one-shot working-tree scan via ``gitleaks dir <repo>``.

    The working-tree equivalent of ``scan_git_history`` and the replacement for
    the old per-file ``gitleaks stdin`` loop (the folded
    "invoke-gitleaks-once-per-repo" todo: ~5,771 spawns / ~50 min on adapt
    collapse to ONE invocation). Stamps ``source="gitleaks"`` so working-tree
    hits keep their faithful attribution. Returns ``[]`` when gitleaks is absent
    or on timeout.
    """
    return _run_gitleaks_target(
        "dir", Path(repo_path), timeout=timeout, source="gitleaks"
    )


def lint_buffer(text: str, *, buffer_name: str) -> None:
    """D-07 chokepoint: raise ``SecretsDetected`` on any hit.

    Caller catches and refuses to write.

    Args:
        text: The buffer to scan (markdown OR JSON sidecar).
        buffer_name: A label for the diagnostic (e.g., ``"markdown"`` or
            ``"json-sidecar"``).

    Raises:
        SecretsDetected: when any rule or entropy hit fires.
    """
    # ``scan_with_entropy`` already composes ``scan_with_known_patterns`` into
    # its result so a single in-process backstop call covers both checks --
    # invoking known-patterns here too would double-count hits.
    hits = scan_with_gitleaks(text) + scan_with_entropy(text)
    if hits:
        raise SecretsDetected(hits, buffer_name)


def lint_and_redact_entropy(
    text: str, *, buffer_name: str
) -> tuple[str, list[dict[str, object]]]:
    """SECRET-LINT-SPLIT-01 (D-051-01/02/03/04): render-local lint-and-redact.

    The locked split for the RENDER path only. Unlike ``lint_buffer`` (which
    hard-blocks on ANY hit and is left UNCHANGED for its 5 non-render callers --
    RESEARCH Pitfall 1), this helper splits the secret-lint chain by confidence:

      * HIGH-confidence layers -- ``scan_with_gitleaks`` + ``scan_with_known_patterns``
        -- STILL HARD-BLOCK: any hit raises ``SecretsDetected`` so the caller
        refuses the write and the CLI exits 2 (D-051-01, fail-loud preserved).
        ``scan_with_known_patterns`` is called DIRECTLY here (NOT via
        ``scan_with_entropy``, which composes it) so the known-pattern slice is
        never downgraded -- a buffer that mixes a benign entropy token AND a real
        ``AKIA``/``ghp_``/``sk_live_`` token still hard-refuses (RESEARCH Pitfall 2).

      * The HEURISTIC entropy backstop (``rule_id == "entropy-backstop"``)
        DOWNGRADES to redact-and-continue: each offending token is replaced in
        place by ``[REDACTED:N]`` (N = original token length) and a value-blind
        log entry is recorded. The cleaned buffer is returned so the report can
        still be written (D-051-04: a benign sha512- lockfile hash becoming
        ``[REDACTED:N]`` is acceptable cosmetic loss; a lost legitimate report
        is not).

    The ``[REDACTED:N]`` marker is itself low-entropy (a short, structured
    literal well below ``ENTROPY_THRESHOLD_BITS_PER_CHAR``), so re-scanning the
    cleaned buffer yields zero entropy-backstop hits and the redaction never
    re-trips the scanner (RESEARCH Pitfall 3 / T-051-08). The
    ``test_no_reflag`` contract pins this invariant.

    Args:
        text: The buffer to scan + redact (markdown OR JSON sidecar).
        buffer_name: A label for the ``SecretsDetected`` diagnostic.

    Returns:
        ``(cleaned_text, redaction_log)`` where ``cleaned_text`` has every
        entropy-backstop token replaced by ``[REDACTED:N]`` and
        ``redaction_log`` is a list of VALUE-BLIND dicts, one per redaction:
        ``{"line": int, "rule_id": "entropy-backstop", "redacted_len": int}``.
        The raw redacted token is NEVER stored (D-051-02 / T-051-07).

    Raises:
        SecretsDetected: when any gitleaks OR known-pattern hit fires -- the
            high-confidence hard-block is preserved for the render path.
    """
    # --- HIGH-confidence layers stay HARD-block (D-051-01). Call known-patterns
    # DIRECTLY so the entropy downgrade below cannot weaken the named-rule slice. ---
    hard_hits = scan_with_gitleaks(text) + scan_with_known_patterns(text)
    if hard_hits:
        raise SecretsDetected(hard_hits, buffer_name)

    # --- HEURISTIC entropy backstop -> redact-and-continue. Re-tokenize per line
    # so we have the (start, end) spans the value-blind SecretHit does not carry. ---
    redaction_log: list[dict[str, object]] = []
    cleaned_lines: list[str] = []
    for lineno, line in enumerate(text.splitlines(keepends=True), start=1):
        # Strip the trailing newline(s) for matching, then re-attach so the
        # buffer's line structure is preserved exactly.
        stripped = line.rstrip("\r\n")
        newline = line[len(stripped):]

        spans: list[tuple[int, int]] = []
        for m in TOKENIZER.finditer(stripped):
            token = m.group(0)
            if len(token) < TOKEN_MIN_LEN:
                continue
            if shannon_entropy_bits_per_char(token) >= ENTROPY_THRESHOLD_BITS_PER_CHAR:
                spans.append((m.start(), m.end()))

        if not spans:
            cleaned_lines.append(line)
            continue

        # Replace right-to-left so earlier offsets stay valid (COPY of the proven
        # render/faithfulness.py span-replace routine -- Don't-Hand-Roll).
        redacted = stripped
        for start, end in sorted(spans, key=lambda s: s[0], reverse=True):
            length = end - start
            redacted = redacted[:start] + f"[REDACTED:{length}]" + redacted[end:]
            # Value-blind log entry: mirrors SecretHit's exposed fields only.
            redaction_log.append(
                {
                    "line": lineno,
                    "rule_id": "entropy-backstop",
                    "redacted_len": length,
                }
            )
        cleaned_lines.append(redacted + newline)

    # Restore the spans-on-each-line into chronological (line, left-to-right)
    # order so the log reads naturally; right-to-left replace above reversed
    # the within-line order.
    redaction_log.sort(key=lambda e: e["line"])

    return "".join(cleaned_lines), redaction_log


def format_diagnostic(hits: list[SecretHit], buffer_name: str) -> str:
    """D-06: stderr-friendly format. NEVER includes the raw value.

    Format per hit: ``<buffer_name>:<line> <rule_id> [REDACTED:<len>]``
    """
    lines = [f"REFUSE: secrets detected in {buffer_name} buffer - write aborted."]
    for h in hits:
        lines.append(
            f"  {buffer_name}:{h.line} {h.rule_id} [REDACTED:{h.redacted_len}]"
        )
    return "\n".join(lines)
