"""D-64 faithfulness gate — strip sentences whose numbers don't trace back.

The chokepoint sibling of secret_lint (D-07) and completion_honesty_lint
(D-32). Runs AFTER both in the render pipeline (Plan 04-08 wires it).
Where the other two RAISE on violation, this one STRIPS sentence-by-
sentence and returns the cleaned prose + a violation log.

Algorithm:
  1. Build AllowedNumbers set deterministically from the Finding store
     BEFORE the agent runs (build_allowed_numbers).
  2. After the agent emits prose, tokenize into paragraphs -> sentences
     (split_sentences with the abbreviation pre-mask per RESEARCH Pitfall 5).
  3. For each sentence, extract numeric tokens via trigger_regex.
  4. Skip tokens matching allowlist_regex (dates, semver, SHAs, ...).
  5. For each remaining token, check: token in AllowedNumbers OR
     min(|t - a| / max(a, 1) for a in allowed) <= tolerance (D-62 5%).
  6. Any non-passing token in a sentence -> strip the whole sentence;
     log a FaithfulnessViolation with the stripped sentence (secret-
     linted per D-64 Claude's Discretion) + offending tokens + nearest_
     allowed for triage.
  7. Empty paragraph -> replace with collapse marker (D-63).
  8. Plan 04-08 detects empty dimension narrative + renders pending-
     marker per D-09 carried-forward.

D-70 exec-summary dilution-strip + D-69 corroboration classes are the
fourth render-time pass and land in Plan 04-08; this module ships the
faithfulness gate alone so the SC-3 structural proof is independent.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from ruamel.yaml import YAML

from repo_audit.agent.schema import FaithfulnessViolation
from repo_audit.render.secret_lint import (
    KNOWN_PATTERNS,
    SecretsDetected,
    lint_buffer,
    scan_with_entropy,
    scan_with_known_patterns,
)

if TYPE_CHECKING:
    from repo_audit.schema.enums import Dimension
    from repo_audit.schema.finding import Finding
    from repo_audit.schema.report import ReportMeta
    from repo_audit.schema.scope_ledger import ScopeLedger
    from repo_audit.schema.trend import TrendDelta


# D-63 abbreviation pre-mask list (RESEARCH Pitfall 5). "Eg." is included as a
# common informal variant the agent may emit; the canonical forms cover the
# rest. Pre-masked before the sentence-boundary regex so a period inside an
# abbreviation never triggers a split.
_ABBREVS: tuple[str, ...] = (
    "i.e.",
    "e.g.",
    "Eg.",
    "vs.",
    "etc.",
    "Mr.",
    "Dr.",
    "Inc.",
    "Ltd.",
)

# D-62 max-depth for the recursive walk_parsed_value (RESEARCH Pitfall 6).
_MAX_WALK_DEPTH = 4

# D-62 small-cardinals seed (narrative-phrasing freedom 0..7).
_SMALL_CARDINALS: set[float] = {float(i) for i in range(8)}

# 7 dimensions (mirror enums.Dimension; hard-coded so we can iterate without
# an import dance at module load).
_DIMENSIONS: tuple[str, ...] = (
    "security",
    "architecture_rot",
    "test_integrity",
    "correctness",
    "quality",
    "process",
    "observability",
)
_SEVERITIES: tuple[str, ...] = ("blocker", "critical", "major", "minor", "info")


def walk_parsed_value(
    obj: object,
    depth: int = 0,
    max_depth: int = _MAX_WALK_DEPTH,
) -> Iterable[float]:
    """Recursively yield numeric leaves from nested parsed_value (RESEARCH Pitfall 6).

    Depth-capped at ``max_depth`` (default 4) so a pathological deeply-nested
    structure cannot blow the stack or balloon the walk. ``bool`` is excluded
    explicitly because it is a subclass of ``int`` in Python and a True/False
    flag is not a "number" the agent should be allowed to quote.
    """
    if depth > max_depth:
        return
    if isinstance(obj, bool):  # bool is subclass of int — exclude explicitly
        return
    if isinstance(obj, (int, float)):
        yield float(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_parsed_value(v, depth + 1, max_depth)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from walk_parsed_value(v, depth + 1, max_depth)


def build_allowed_numbers(
    findings: list[Finding],
    scope_ledger: ScopeLedger,
    meta: ReportMeta,
    *,
    trend: "TrendDelta | None" = None,
) -> set[float]:
    """D-62: build the AllowedNumbers set deterministically BEFORE the agent runs.

    The set seeds:
      * small cardinals 0..7 (narrative-phrasing freedom);
      * every numeric leaf from every finding's ``evidence.parsed_value``
        (recursively, depth-capped) plus any line-range endpoints;
      * per-dimension finding counts (the agent may quote "3 security findings");
      * per-severity finding counts;
      * the three scope-ledger cardinalities (scanned/skipped/unavailable);
      * when ``trend`` is provided (Plan 05-03 / RESEARCH Pitfall 1): every
        non-None delta magnitude (signed AND absolute), every per-dimension
        finding-count delta, AND the prior baseline absolute totals. Trend
        deltas are NOT findings, so without this fold the agent's
        ``trend_narrative`` sentences ("rose from 120 to 134 (+14)") would be
        silently stripped by the gate. Folding the prior totals + delta
        magnitudes lets all three of those numbers pass while a fabricated
        number (not in the trend) is still stripped (the load-bearing
        negative-control invariant — see test_trend_faithfulness.py).

    ``meta`` is accepted for forward-compatibility (later phases may fold in
    meta-level counts such as contributor totals); the v1 seed does not read
    it, keeping the construction purely a function of the Finding store +
    scope ledger (+ the optional trend) so it is reproducible across runs.
    """
    _ = meta  # reserved for meta-derived counts; the seed is store+trend only.
    allowed: set[float] = set(_SMALL_CARDINALS)

    # All numeric leaves from every finding's parsed_value.
    for f in findings:
        ev = getattr(f, "evidence", None)
        if ev is None:
            continue
        parsed = getattr(ev, "parsed_value", None)
        if parsed is not None:
            allowed.update(walk_parsed_value(parsed))
        # Also include line-range endpoints if present.
        line_range = getattr(ev, "line_range", None)
        if (
            line_range
            and isinstance(line_range, (tuple, list))
            and len(line_range) == 2
        ):
            try:
                allowed.add(float(line_range[0]))
                allowed.add(float(line_range[1]))
            except (TypeError, ValueError):
                pass

    # Per-dimension counts (the agent may quote these in narrative).
    for d in _DIMENSIONS:
        allowed.add(float(sum(1 for f in findings if getattr(f, "dimension", "") == d)))
    # Per-severity counts.
    for s in _SEVERITIES:
        allowed.add(float(sum(1 for f in findings if getattr(f, "severity", "") == s)))

    # Scope-ledger cardinalities.
    allowed.add(float(len(getattr(scope_ledger, "scanned", []) or [])))
    allowed.add(float(len(getattr(scope_ledger, "skipped", []) or [])))
    allowed.add(float(len(getattr(scope_ledger, "unavailable", []) or [])))

    # Plan 05-03 (RESEARCH Pitfall 1): fold the trend numbers so the agent's
    # trend_narrative survives the gate. Trend deltas are not findings, so they
    # must be admitted explicitly here.
    if trend is not None:
        # Each metric-family delta (signed AND absolute) — n/a (None) skipped.
        for delta in (
            getattr(trend, "commits_delta", None),
            getattr(trend, "loc_delta", None),
            getattr(trend, "lint_error_delta", None),
            getattr(trend, "coverage_delta", None),
        ):
            if delta is not None:
                allowed.add(float(delta))
                allowed.add(abs(float(delta)))
        # Per-dimension finding-count deltas (signed AND absolute).
        for count_delta in (
            getattr(trend, "finding_count_delta_by_dimension", {}) or {}
        ).values():
            allowed.add(float(count_delta))
            allowed.add(abs(float(count_delta)))
        # Prior baseline absolute totals (the "from X" half of "from X to Y").
        for total in (getattr(trend, "prior_totals", {}) or {}).values():
            try:
                allowed.add(float(total))
            except (TypeError, ValueError):
                pass

    return allowed


def load_faithfulness_allowlist(
    config_path: str | None = None,
) -> tuple[re.Pattern, re.Pattern]:
    """Load ``(trigger_regex, allowlist_regex)`` from packaged faithfulness.yaml.

    ``config_path`` None loads the packaged default. Phase 7 user-overlay will
    pass a target-repo ``.repo-audit.yaml``-derived path here.

    Uses ``YAML(typ='safe')`` per the Phase 3 T-03-01 mitigation carried
    forward — never the unsafe full loader (refuses ``!!python/object``
    constructors so a hostile overlay cannot smuggle code execution).
    """
    if config_path is None:
        from importlib.resources import files

        config_path = str(
            files("repo_audit.render").joinpath("faithfulness.yaml")
        )
    yaml = YAML(typ="safe")
    with open(config_path, encoding="utf-8") as fh:
        config = yaml.load(fh) or {}
    trigger = re.compile(config["trigger_regex"])
    allowlist = re.compile(config["allowlist_regex"])
    return trigger, allowlist


def split_sentences(prose: str) -> list[str]:
    """D-63 sentence tokenizer with abbreviation pre-mask (RESEARCH Pitfall 5).

    Abbreviations are replaced with NUL-delimited placeholders before the
    boundary regex runs, then restored — so a period inside "e.g." never
    splits a sentence. The boundary regex is the D-63 lock
    ``(?<=[.!?])\\s+(?=[A-Z])``.
    """
    masked = prose
    placeholders: dict[str, str] = {}
    for i, abbr in enumerate(_ABBREVS):
        ph = f"\x00ABBR{i}\x00"
        placeholders[ph] = abbr
        masked = masked.replace(abbr, ph)
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z])", masked)
    out: list[str] = []
    for part in parts:
        for ph, abbr in placeholders.items():
            part = part.replace(ph, abbr)
        if part.strip():
            out.append(part)
    return out


def _token_passes(
    token: str,
    allowed: set[float],
    allowlist: re.Pattern,
    tolerance: float,
) -> tuple[bool, float | None]:
    """Return ``(passes, nearest_allowed-or-None)`` for one numeric token.

    A token passes if it matches the allowlist (dates/semver/SHAs/...), is in
    AllowedNumbers exactly, or is within ``tolerance`` relative distance of
    some allowed value: ``|t - a| / max(a, 1) <= tolerance`` (D-62 5%).
    """
    if allowlist.search(token):
        return True, None
    cleaned = token.replace(",", "").rstrip("%")
    try:
        value = float(cleaned)
    except ValueError:
        return True, None  # not actually a numeric token; let it through
    if value in allowed:
        return True, value
    if not allowed:
        return False, None
    nearest = min(allowed, key=lambda a: abs(value - a) / max(abs(a), 1.0))
    relative = abs(value - nearest) / max(abs(nearest), 1.0)
    if relative <= tolerance:
        return True, nearest
    return False, nearest


def _redact_secrets_in_sentence(sentence: str) -> str:
    """D-64 Claude's Discretion: secret-lint the original_sentence before storing.

    A hallucinated secret in agent prose must not survive into the JSON
    sidecar's audit log (the sidecar is itself user-facing once Phase 5's
    fleet aggregator reads it). Defense in depth — the render chokepoint's
    secret_lint also catches at write time.

    NOTE (Plan 04-07 Rule-1 deviation from the plan's example): the Phase 1
    ``SecretHit`` dataclass exposes ``line``/``rule_id``/``redacted_len`` and
    has NO ``.start``/``.end`` offsets, so the plan's span-based redaction
    sketch cannot run as written. Instead we re-run the known-pattern regex
    table directly over the sentence to locate spans and replace each match
    with ``[REDACTED:N]`` in place (right-to-left so offsets stay valid). We
    additionally call the line-oriented scanners as a tripwire so that if a
    secret is detected but not span-locatable we still scrub conservatively.
    The redaction is defense-in-depth, not load-bearing; on any scanner-shape
    divergence we degrade to "no redaction" and rely on the render chokepoint.
    """
    redacted = sentence
    try:
        # Re-run the known-pattern table to get matchable spans. KNOWN_PATTERNS
        # is the authoritative structural-shape table (AWS/GitHub/Stripe/...).
        spans: list[tuple[int, int]] = []
        for _rule_id, pattern in KNOWN_PATTERNS:
            for m in pattern.finditer(redacted):
                spans.append((m.start(), m.end()))
        # Apply right-to-left so earlier positions stay valid.
        for start, end in sorted(spans, key=lambda s: s[0], reverse=True):
            length = end - start
            redacted = redacted[:start] + f"[REDACTED:{length}]" + redacted[end:]
    except Exception:
        # Defense-in-depth path only; never let redaction failure abort the gate.
        return sentence

    # Tripwire: if the line-oriented scanners still find a hit (e.g. a high-
    # entropy token the prefix table missed), scrub the whole sentence rather
    # than leak it. This favors the audit log's safety over readability.
    try:
        leftover = scan_with_known_patterns(redacted) + scan_with_entropy(redacted)
    except Exception:
        leftover = []
    if leftover:
        total = sum(getattr(h, "redacted_len", 0) for h in leftover)
        return f"[REDACTED:{total}]"
    return redacted


def check_faithfulness(
    prose: str,
    allowed_numbers: set[float],
    trigger_regex: re.Pattern,
    allowlist_regex: re.Pattern,
    *,
    tolerance: float = 0.05,
    dimension: Dimension | None = None,
) -> tuple[str, list[FaithfulnessViolation]]:
    """D-64 — return ``(clean_prose, violations)``. Sentence-level strip.

    Never raises. The gate STRIPS; it does not abort (unlike secret_lint and
    completion_honesty_lint which RAISE). Plan 04-08 wires it at the render
    chokepoint AFTER those two. The asymmetry is intentional — faithfulness is
    "fix and continue"; secrets/completion-dishonesty are "abort the write".
    """
    if not prose:
        return prose, []
    paragraphs = prose.split("\n\n")
    clean_paragraphs: list[str] = []
    violations: list[FaithfulnessViolation] = []
    for p_idx, paragraph in enumerate(paragraphs):
        sentences = split_sentences(paragraph)
        if not sentences:
            # Preserve deliberate blank/whitespace-only paragraph spacing.
            clean_paragraphs.append(paragraph)
            continue
        kept: list[str] = []
        for sentence in sentences:
            # Mask allowlisted spans (dates, semver, SHAs, TS codes, ...) BEFORE
            # extracting numeric tokens. A date like 2026-01-01 must be treated
            # as one allowlisted unit; otherwise the trigger regex would split
            # it into 2026 / 01 / 01 at the hyphen word-boundaries and the
            # allowlist check on the bare "2026" token would never fire
            # (the allowlist pattern needs the full YYYY-MM-DD shape).
            scan_target = allowlist_regex.sub(" ", sentence)
            tokens = trigger_regex.findall(scan_target)
            offending: list[str] = []
            nearest_for_violation: float | None = None
            for token in tokens:
                passes, nearest = _token_passes(
                    token, allowed_numbers, allowlist_regex, tolerance
                )
                if not passes:
                    offending.append(token)
                    if nearest_for_violation is None:
                        nearest_for_violation = nearest
            if offending:
                redacted = _redact_secrets_in_sentence(sentence)
                violations.append(
                    FaithfulnessViolation(
                        original_sentence=redacted,
                        offending_tokens=offending,
                        dimension=dimension,
                        paragraph_index=p_idx,
                        nearest_allowed=nearest_for_violation,
                    )
                )
            else:
                kept.append(sentence)
        if not kept:
            # D-63 empty-paragraph collapse marker.
            stripped_count = len(sentences)
            clean_paragraphs.append(
                f"_({stripped_count} sentence(s) elided by faithfulness gate "
                "— see JSON sidecar)_"
            )
        else:
            clean_paragraphs.append(" ".join(kept))
    return "\n\n".join(clean_paragraphs), violations


# dilution_strip_exec_summary (D-70) is intentionally deferred to Plan 04-08
# per the plan's must_haves; this module ships the faithfulness gate alone.

__all__ = [
    "build_allowed_numbers",
    "check_faithfulness",
    "load_faithfulness_allowlist",
    "split_sentences",
    "walk_parsed_value",
]

# Re-exported names the plan asks render/__init__ to expose are surfaced via
# render/__init__.py. lint_buffer / SecretsDetected are imported above so the
# defense-in-depth tripwire path can reference the Phase 1 chokepoint API.
_ = (lint_buffer, SecretsDetected)
