"""git_status snapshot + diff tests. STRICT — lands in Plan 02-01a Task 2."""
from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

from repo_audit.meta.git_status import diff_git_status, snapshot_git_status


def test_snapshot_non_git_path_returns_empty(tmp_path):
    assert snapshot_git_status(tmp_path / "no-such") == set()


def test_snapshot_clean_repo_returns_empty(fake_repo):
    repo = fake_repo({"README.md": "# x\n"}, name="clean")
    assert snapshot_git_status(repo) == set()


def test_snapshot_uses_no_optional_locks_flag(monkeypatch, tmp_path):
    """Pitfall 9: --no-optional-locks must be in the argv list."""
    captured: dict[str, list[str]] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "repo_audit.meta.git_status.subprocess.run", fake_run
    )
    snapshot_git_status(tmp_path)
    assert "--no-optional-locks" in captured["argv"]


def test_diff_returns_empty_on_no_change():
    assert diff_git_status({" M src/x.py"}, {" M src/x.py"}) == []


def test_diff_excludes_allowed_prefix():
    pre: set[str] = set()
    post = {"?? docs/state-reports/x.md", "?? docs/state-reports/x.json"}
    assert diff_git_status(pre, post, allowed_prefix="docs/state-reports/") == []


def test_diff_surfaces_unexpected_addition():
    pre: set[str] = set()
    post = {"?? .eslintcache", "?? docs/state-reports/x.md"}
    offenders = diff_git_status(pre, post)
    assert len(offenders) == 1
    assert ".eslintcache" in offenders[0]


def test_diff_handles_rename_format():
    pre: set[str] = set()
    post = {"R  old.txt -> docs/state-reports/new.md"}
    # New path is under allowed prefix → no offender
    assert diff_git_status(post=post, pre=pre, allowed_prefix="docs/state-reports/") == []
