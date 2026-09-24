"""Faithfulness-gate tests for SC-3, D-61, D-62, D-63, D-64.

Each test in this file flipped from SKIPPED to ACTIVE once
``repo_audit.render.faithfulness`` landed in Plan 04-07. The
``importorskip`` gate stays so the file degrades to SKIPPED on a tree that
predates the module rather than ERRORing.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_invented_coverage_pct_stripped             (SC-3/D-64 — load-bearing structural proof)
- test_invented_contributor_count_stripped        (D-64 — invented contributor count stripped)
- test_invented_coverage_delta_stripped           (D-64 — invented coverage delta stripped)
- test_every_file_passes_stripped                 (D-64 — defense in depth w/ completion_honesty)
- test_invented_date_stripped                     (D-64 — invented date stripped)
- test_comma_grouped_loc_passes                   (D-61, RESEARCH Pitfall 4 — 18,432 == {18432})
- test_semver_passes_via_allowlist                (D-61 — semver allowlist)
- test_abbreviation_split_correct                 (D-63, RESEARCH Pitfall 5 — abbreviation pre-mask)
- test_empty_paragraph_collapse                   (D-63 — empty paragraph collapse)
- test_empty_dimension_renders_pending            (D-63 — empty dimension renders pending)
- test_meta_violations_record                     (D-64 — violations recorded into meta)
- test_violation_original_sentence_is_secret_linted(D-64 + discretion — defense in depth)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.render.faithfulness",
    reason="optional module repo_audit.render.faithfulness not importable — feature not present in this build, or the install is incomplete",
)

from repo_audit.render.faithfulness import (  # noqa: E402
    check_faithfulness,
    load_faithfulness_allowlist,
    split_sentences,
)


@pytest.fixture
def regexes():
    """The packaged (trigger, allowlist) pair under test."""
    return load_faithfulness_allowlist()


@pytest.fixture
def small_cardinals():
    """The D-62 small-cardinals-only AllowedNumbers seed (nothing invented passes)."""
    return {float(i) for i in range(8)}


def test_invented_coverage_pct_stripped(regexes, small_cardinals, adversarial_narrative_corpus):
    """SC-3/D-64: an invented coverage percentage is stripped (load-bearing)."""
    trigger, allowlist = regexes
    prose = adversarial_narrative_corpus["invented_coverage_pct"]
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    # The whole single-sentence paragraph strips -> elision marker (or empty).
    assert clean.strip() == "" or "elided" in clean.lower()
    assert len(violations) == 1
    assert violations[0].original_sentence == prose
    assert any("73" in t for t in violations[0].offending_tokens)


def test_invented_contributor_count_stripped(regexes, small_cardinals, adversarial_narrative_corpus):
    """D-64: an invented contributor count is stripped."""
    trigger, allowlist = regexes
    prose = adversarial_narrative_corpus["invented_contributor_count"]
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert clean.strip() == "" or "elided" in clean.lower()
    assert len(violations) == 1
    assert any("99" in t for t in violations[0].offending_tokens)


def test_invented_coverage_delta_stripped(regexes, small_cardinals):
    """D-64: an invented coverage delta is stripped."""
    trigger, allowlist = regexes
    prose = "Coverage dropped 14 percentage points."
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert clean.strip() == "" or "elided" in clean.lower()
    assert len(violations) == 1
    assert any("14" in t for t in violations[0].offending_tokens)


def test_every_file_passes_stripped(regexes, small_cardinals, adversarial_narrative_corpus):
    """D-64: 'every file passes' has no numeric token — the faithfulness gate KEEPS it.

    (completion_honesty_lint is the gate that would strip on partial=True;
    the faithfulness gate alone, with no numeric tokens, keeps the sentence.)
    """
    trigger, allowlist = regexes
    prose = adversarial_narrative_corpus["every_file_smuggling"]
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert clean.strip() == prose.strip()
    assert violations == []


def test_invented_date_stripped(regexes, small_cardinals):
    """D-64: a date matches the allowlist regex so the sentence is KEPT.

    The year/month/day numerals are NOT candidates because the allowlist
    matches the YYYY-MM-DD token first. The gate keeps the sentence even
    though 2026 is not in AllowedNumbers.
    """
    trigger, allowlist = regexes
    prose = "The prior report was dated 2026-01-01 for reference."
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert clean.strip() == prose.strip()
    assert violations == []


def test_comma_grouped_loc_passes(regexes, adversarial_narrative_corpus):
    """D-61 (RESEARCH Pitfall 4): comma-grouped LOC 18,432 matches {18432}."""
    trigger, allowlist = regexes
    allowed = {18432.0, 0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0}
    prose = adversarial_narrative_corpus["authentic_loc"]
    clean, violations = check_faithfulness(prose, allowed, trigger, allowlist)
    assert "18,432" in clean
    assert violations == []


def test_semver_passes_via_allowlist(regexes, small_cardinals, adversarial_narrative_corpus):
    """D-61: a semver string passes via the allowlist."""
    trigger, allowlist = regexes
    prose = adversarial_narrative_corpus["authentic_semver"]
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert "1.19.2" in clean
    assert violations == []


def test_abbreviation_split_correct():
    """D-63 (RESEARCH Pitfall 5): abbreviation pre-mask splits sentences correctly."""
    sentences = split_sentences("Eg. The agent invented 73. The next sentence is fine.")
    assert len(sentences) == 2
    assert "73" in sentences[0]
    assert "73" not in sentences[1]
    assert "fine" in sentences[1]


def test_empty_paragraph_collapse(regexes, small_cardinals):
    """D-63: a paragraph where every sentence strips collapses to the elision marker."""
    trigger, allowlist = regexes
    prose = "Coverage is 73% here. Contributors number 99 too."
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert "elided by faithfulness gate" in clean
    assert "JSON sidecar" in clean
    assert len(violations) == 2


def test_empty_dimension_renders_pending(regexes, small_cardinals):
    """D-63: when all paragraphs collapse, the cleaned prose is only the elision marker.

    Plan 04-08 wires the dimension-level pending fallback; here we assert
    check_faithfulness returns enough state for that detection — i.e. the
    cleaned prose contains no surviving narrative, only the marker.
    """
    trigger, allowlist = regexes
    prose = "Coverage is 73% across the suite."
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert "elided by faithfulness gate" in clean
    # No narrative survived: stripping the marker leaves nothing alphabetic
    # that came from the agent's prose.
    assert "Coverage" not in clean
    assert len(violations) == 1


def test_meta_violations_record(regexes, small_cardinals):
    """D-64: violations is a list[FaithfulnessViolation] with the D-64 shape."""
    from repo_audit.agent.schema import FaithfulnessViolation

    trigger, allowlist = regexes
    prose = "Coverage is 73% across the suite."
    _, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert isinstance(violations, list)
    assert all(isinstance(v, FaithfulnessViolation) for v in violations)
    assert violations[0].nearest_allowed is not None
    assert violations[0].paragraph_index == 0


def test_violation_original_sentence_is_secret_linted(regexes, small_cardinals):
    """D-64 + discretion: a hallucinated secret in a stripped sentence is redacted.

    The canonical AWS-example key inside an invented-number sentence must be
    REPLACED with a [REDACTED:N] marker on the stored FaithfulnessViolation.
    """
    trigger, allowlist = regexes
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    prose = f"Coverage is 73% and the key {aws_key} leaked."
    _, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert len(violations) == 1
    assert aws_key not in violations[0].original_sentence
    assert "[REDACTED:" in violations[0].original_sentence


# ---- Regex loopholes: tokens the gate used to skip must now be inspected. ----


@pytest.mark.parametrize(
    "prose",
    [
        "Coverage is 45.7%.",          # decimal percentage (was masked as semver)
        "It grew by 12k lines.",       # unit suffix (was not tokenised at all)
        "It is 9000x faster.",         # multiplier suffix
        "The count is 12.",            # sentence-final period
        "The id is 1234567.",          # bare 7-digit integer (was masked as a SHA)
    ],
)
def test_loophole_tokens_are_stripped(regexes, small_cardinals, prose):
    trigger, allowlist = regexes
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert len(violations) == 1, (prose, violations)
    assert prose not in clean


def test_traceable_decimal_percentage_is_kept(regexes, small_cardinals):
    trigger, allowlist = regexes
    prose = "Coverage is 45.7%."
    allowed = small_cardinals | {45.7}
    clean, violations = check_faithfulness(prose, allowed, trigger, allowlist)
    assert violations == []
    assert clean.strip() == prose


@pytest.mark.parametrize(
    "prose",
    [
        "Commit abc1234 fixed it.",       # hex SHA with a letter is still masked
        "Upgrade to v1.2 or 1.2.3.",      # prefixed / three-part semver still masked
        "Scanned on 2026-09-23 again.",   # ISO date still masked
    ],
)
def test_structural_tokens_still_masked(regexes, small_cardinals, prose):
    trigger, allowlist = regexes
    clean, violations = check_faithfulness(prose, small_cardinals, trigger, allowlist)
    assert violations == [], (prose, violations)
    assert clean.strip() == prose
