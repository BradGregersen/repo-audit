"""VER-02 — positive reachability is an independent 2nd signal; negative/unknown
NEVER deletes/demotes (SAFE-01 downgrade-safe, D-17-03).

Made real in Plan 17-01 Task 1.

``check_reachable(finding, repo_path) -> bool | None``:
  * True  — the finding's target symbol/token IS present (imported, for .py).
  * False — the symbol/token is absent.
  * None  — not checked / unknown stack / any error (NEVER raises).

The target symbol is read from ``finding.evidence.parsed_value['symbol']`` (the
reachability target a collector annotates), falling back to ``rule_id``.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.verification.reachability import check_reachable


def test_python_symbol_present_returns_true(fake_finding, fake_repo_with_source):
    f = fake_finding(
        file="src/app/auth.py",
        parsed_value={"symbol": "token_hex"},
    )
    assert check_reachable(f, fake_repo_with_source) is True


def test_python_symbol_absent_returns_false(fake_finding, fake_repo_with_source):
    f = fake_finding(
        file="src/app/auth.py",
        parsed_value={"symbol": "nonexistent_symbol_xyz"},
    )
    assert check_reachable(f, fake_repo_with_source) is False


def test_non_python_token_present_returns_true(fake_finding, fake_repo_with_source):
    f = fake_finding(
        family="sast",
        file="src/app/ui.ts",
        parsed_value={"symbol": "dangerouslySetInnerHTML"},
    )
    assert check_reachable(f, fake_repo_with_source) is True


def test_non_python_token_absent_returns_false(fake_finding, fake_repo_with_source):
    f = fake_finding(
        family="sast",
        file="src/app/ui.ts",
        parsed_value={"symbol": "noSuchTokenHere"},
    )
    assert check_reachable(f, fake_repo_with_source) is False


def test_missing_file_returns_none(fake_finding, tmp_path):
    """An unreadable/absent target file returns None (not-checked) and never raises."""
    f = fake_finding(file="does/not/exist.py", parsed_value={"symbol": "x"})
    assert check_reachable(f, tmp_path) is None


def test_no_symbol_to_check_returns_none(fake_finding, fake_repo_with_source):
    """No resolvable symbol/token target → None, never a deletion signal."""
    f = fake_finding(file="src/app/auth.py", rule_id="", parsed_value={})
    assert check_reachable(f, fake_repo_with_source) is None


def test_unreachable_never_drops(fake_finding, fake_repo_with_source, tmp_path):
    """VER-02/D-17-03: a negative AND an unknown reachability both return a
    non-True tri-state value — never a deletion/demotion signal handed to the
    caller. The function NEVER raises on any of these inputs.
    """
    # Negative: symbol genuinely absent.
    absent = fake_finding(
        file="src/app/auth.py", parsed_value={"symbol": "definitely_absent"}
    )
    neg = check_reachable(absent, fake_repo_with_source)
    assert neg is False

    # Unknown: file missing entirely.
    unknown = fake_finding(file="missing.py", parsed_value={"symbol": "x"})
    unk = check_reachable(unknown, tmp_path)
    assert unk is None

    # Neither False nor None is the value True (the ONLY corroborating signal);
    # the caller therefore never receives anything it could read as "delete".
    assert neg is not True
    assert unk is not True


def test_never_raises_on_garbage_repo_path(fake_finding):
    """A nonsense repo path returns None rather than raising (D-17-03 never-raise)."""
    f = fake_finding(file="src/app/auth.py", parsed_value={"symbol": "x"})
    result = check_reachable(f, Path("/this/path/does/not/exist/anywhere"))
    assert result is None
