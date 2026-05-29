"""Shared pytest fixtures for Phase 1 tests.

Fixture names defined here are referenced by every Phase 1 test file.
Changing a name here means updating every test that imports it.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pygit2
import pytest
from typer.testing import CliRunner


# --- Synthetic secret for REP-05 / SAFE-secret-lint tests ---
# AWS-key-shaped string with high enough Shannon entropy (>4.5 bits/char) to fire
# the entropy backstop AND match the gitleaks AWS access-key rule. NOT a real key.
_SYNTHETIC_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # 20 chars, AWS canonical example


@pytest.fixture
def synthetic_secret() -> str:
    """A known fake AWS access key for secret-lint tests.

    Used by tests/test_secret_lint.py to inject a synthetic high-entropy token
    into a render buffer and assert the secret-lint refuses the write.
    """
    return _SYNTHETIC_AWS_KEY


@pytest.fixture
def runner() -> CliRunner:
    """typer.testing.CliRunner instance (in-process invocation, no subprocess).

    Modern Typer/Click already separates stdout/stderr by default; the
    historical ``mix_stderr=False`` kwarg was removed (Rule 3 blocking
    auto-fix during Plan 01-05 -- previously masked by the module-level
    xfail on tests/test_secret_lint.py and the per-function xfails on
    tests/test_cli.py).
    """
    return CliRunner()


def _seed_repo(
    repo_path: Path,
    manifests: dict[str, str],
    *,
    commit_message: str = "init",
    commit_timestamp: int | None = None,
) -> Path:
    """Seed a git repo at repo_path with the given manifest files and one commit."""
    repo_path.mkdir(parents=True, exist_ok=True)
    repo = pygit2.init_repository(str(repo_path), bare=False)
    for rel_path, contents in manifests.items():
        f = repo_path / rel_path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(contents, encoding="utf-8")
    # Stage all
    repo.index.add_all()
    repo.index.write()
    tree = repo.index.write_tree()
    ts = commit_timestamp or int(_dt.datetime(2026, 5, 28, 12, 0, 0).timestamp())
    sig = pygit2.Signature("test-author", "test@example.com", ts, 0)
    repo.create_commit("HEAD", sig, sig, commit_message, tree, [])
    return repo_path


@pytest.fixture
def fake_repo(tmp_path):
    """Factory: build a pygit2-seeded fake repo with chosen manifests.

    Usage:
        def test_x(fake_repo):
            repo = fake_repo({"package.json": "{}", "tsconfig.json": "{}"})
            # repo is a Path with one commit; manifests written and committed
    """
    def _factory(manifests: dict[str, str] | None = None, *, name: str = "fake-repo") -> Path:
        repo_path = tmp_path / name
        return _seed_repo(repo_path, manifests or {})
    return _factory


@pytest.fixture
def polyglot_repo(tmp_path) -> Path:
    """A repo mirroring ~/Code/adapt's shape: TypeScript + Supabase.

    Used by tests/test_detect.py::test_detect_polyglot_repo and
    tests/test_cli.py::test_detect_command_lists_stacks.
    """
    return _seed_repo(
        tmp_path / "polyglot",
        {
            "package.json": '{"name": "polyglot", "dependencies": {"typescript": "^5.0.0"}}',
            "tsconfig.json": '{"compilerOptions": {"strict": true}}',
            "supabase/config.toml": '[api]\nport = 54321\n',
        },
    )


@pytest.fixture
def expo_supabase_repo(tmp_path) -> Path:
    """An Expo + Supabase repo: should detect BOTH stacks (Expo overrides plain TS)."""
    return _seed_repo(
        tmp_path / "expo-supabase",
        {
            "package.json": '{"name": "rn-app", "dependencies": {"expo": "~54.0.0"}}',
            "app.json": '{"expo": {"name": "rn-app"}}',
            "supabase/config.toml": "[api]\nport = 54321\n",
        },
    )


@pytest.fixture
def empty_repo(tmp_path) -> Path:
    """A repo with no recognized manifests (DETECT-03 — should return empty stack list)."""
    return _seed_repo(
        tmp_path / "empty-repo",
        {"README.md": "# empty\n"},
    )


# --- Phase 2 additions: multi-commit factory for COLL-01 cadence tests ---
import datetime as _dt2  # re-aliased to avoid colliding with the existing _dt import
from typing import Optional


@pytest.fixture
def fake_repo_with_commits(tmp_path):
    """Factory: build a pygit2-seeded fake repo with N commits, controllable authors + timestamps.

    Usage:
        def test_cadence(fake_repo_with_commits):
            repo = fake_repo_with_commits(
                n_commits=5,
                authors=["a@x.com", "a@x.com", "b@x.com", "b@x.com", "a@x.com"],
                days_ago_list=[0, 1, 2, 8, 35],  # for 7d/30d/60d/90d bucketing
                name="cadence-test",
            )
    """
    def _factory(
        *,
        n_commits: int = 1,
        authors: Optional[list[str]] = None,
        days_ago_list: Optional[list[int]] = None,
        name: str = "fake-repo-multi",
        manifests: Optional[dict[str, str]] = None,
    ) -> Path:
        authors = authors or [f"author{i}@example.com" for i in range(n_commits)]
        assert len(authors) == n_commits, "authors length must equal n_commits"
        days_ago_list = days_ago_list or [i for i in range(n_commits)]
        assert len(days_ago_list) == n_commits, "days_ago_list length must equal n_commits"
        repo_path = tmp_path / name
        repo_path.mkdir(parents=True, exist_ok=True)
        repo = pygit2.init_repository(str(repo_path), bare=False)
        # Seed initial manifest set (optional)
        for rel_path, contents in (manifests or {}).items():
            f = repo_path / rel_path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(contents, encoding="utf-8")
        today = _dt2.datetime(2026, 5, 28, 12, 0, 0)
        parents: list[str] = []
        for i in range(n_commits):
            # Create a unique file per commit so the tree changes
            marker = repo_path / f"_commit_marker_{i}.txt"
            marker.write_text(f"commit {i}\n", encoding="utf-8")
            repo.index.add_all()
            repo.index.write()
            tree = repo.index.write_tree()
            ts = int((today - _dt2.timedelta(days=days_ago_list[i])).timestamp())
            sig = pygit2.Signature(authors[i].split("@")[0], authors[i], ts, 0)
            oid = repo.create_commit(
                "HEAD", sig, sig, f"commit {i}", tree, parents,
            )
            parents = [str(oid)]
        return repo_path

    return _factory


# ---- Phase 4 Plan 04-09: hermetic agent default for the deterministic suite ----


@pytest.fixture(autouse=True)
def _stub_agent_session(monkeypatch):
    """Make ``repo-audit scan``'s default agent loop a hermetic no-op (Plan 04-09).

    Plan 04-09 wired ``run_agent_session`` to run by default on ``repo-audit scan``
    (only ``--no-agent`` skips it). Pre-existing Phase 1-3 CLI/render tests
    invoke ``scan`` without ``--no-agent`` and assert the DETERMINISTIC report
    shape — they must not depend on a live Claude Code CLI being reachable
    (slow + environment-dependent + occasionally non-deterministic).

    This autouse fixture replaces ``session.run_agent_session`` with an async
    no-op that returns ``(None, meta)`` and leaves ``meta.agent_status`` as-is
    (None) — exactly the deterministic-only render path. Tests that want to
    exercise the real loop (e.g. the agent-session unit tests) construct their
    own ``ClaudeSDKClient`` mock directly and never go through cli.scan; tests
    that assert the wiring (test_cli_no_agent_flag.py) monkeypatch their own
    spy AFTER this fixture, which takes precedence.
    """
    try:
        import repo_audit.agent.session as _session_mod
    except Exception:  # pragma: no cover — agent package always present in P4
        return

    async def _noop_run_agent_session(**kwargs):
        # Deterministic-only path: return no agent_output, meta untouched.
        return None, kwargs["meta"]

    monkeypatch.setattr(
        _session_mod, "run_agent_session", _noop_run_agent_session
    )


# ---- Phase 4 Wave 0 fixtures (added by plan 04-01-PLAN.md) ----


@pytest.fixture
def mock_sdk_client():
    """Factory: returns an AsyncMock-based fake ClaudeSDKClient.

    Usage:
        client = mock_sdk_client(messages=[
            AssistantMessage(content=[ToolUseBlock(id='1', name='get_tsc_diagnostics', input={})], model='claude-sonnet-4-5', usage={'input_tokens': 100, 'output_tokens': 50}),
            ResultMessage(subtype='success', duration_ms=1234, duration_api_ms=1000, is_error=False, num_turns=2, session_id='s1', total_cost_usd=0.01234),
        ])
        async with client as c:
            async for msg in c.receive_messages():
                ...

    RESEARCH §"Validation Architecture (Nyquist)" -> Test Framework:
    "for SDK message-stream mocking, use unittest.mock.AsyncMock against
    ClaudeSDKClient" -- this factory wires that pattern in one place so
    every test_agent_*.py file does not reinvent it.
    """
    from unittest.mock import AsyncMock

    def _factory(messages):
        client = AsyncMock()

        async def _receive_messages():
            for m in messages:
                yield m

        client.receive_messages = _receive_messages
        client.connect = AsyncMock()
        client.disconnect = AsyncMock()
        client.query = AsyncMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        return client

    return _factory


@pytest.fixture
def agent_scan_report_factory():
    """Factory: returns a minimally-valid AgentScanReport.

    Importorskip-gated so the fixture is only constructed when
    repo_audit.agent.schema actually lands (Plan 04-02).
    """
    pytest.importorskip(
        "repo_audit.agent.schema",
        reason="agent.schema lands in Plan 04-02; fixture skipped until then.",
    )
    from repo_audit.agent.schema import AgentScanReport

    def _factory(**overrides):
        base = dict(
            dimensions=[],
            executive_summary="Baseline summary.",
            cross_cutting_notes=None,
        )
        base.update(overrides)
        return AgentScanReport(**base)

    return _factory


@pytest.fixture
def allowed_numbers_factory():
    """Factory: returns a populated set[float] matching D-62's shape.

    Default seed includes the small-cardinals {0..7} (D-62 narrative-phrasing
    freedom) plus a sample LCOV-shape number (73.4 -- used by SC-3 sibling
    cases). Override by passing extra=[...].
    """
    def _factory(extra=None):
        base = {float(i) for i in range(8)}
        base.add(73.4)
        base.add(18432.0)
        base.add(152625.0)
        if extra:
            base.update(float(x) for x in extra)
        return base

    return _factory


@pytest.fixture
def adversarial_narrative_corpus():
    """Named adversarial prose snippets for faithfulness-gate tests.

    Each key is a test scenario; each value is a string fragment the
    Wave 3 tests pass to check_faithfulness(...) with a known
    AllowedNumbers set and assert the stripping behavior.

    Keys (test scenario -> expected behavior):
        invented_coverage_pct      -> "Coverage is 73% across the suite."
                                      (no LCOV finding within 5% of 73 -> strip)
        invented_contributor_count -> "There are 99 contributors active this month."
                                      (no meta.contributor_count near 99 -> strip)
        authentic_loc              -> "The repo has 18,432 LOC."
                                      (AllowedNumbers={18432} -> keep)
        authentic_semver           -> "Pinned at pygit2 1.19.2."
                                      (allowlist regex matches -> keep)
        abbreviation_split         -> "Eg. The agent invented 73. The next sentence is fine."
                                      (D-63 pre-mask handles 'Eg.' -> only the
                                       '73' sentence strips; the next stays)
        every_file_smuggling       -> "Every file passes lint."
                                      (caught by completion_honesty too;
                                       faithfulness gate keeps numbers,
                                       completion_honesty handles 'every')
    """
    return {
        "invented_coverage_pct": "Coverage is 73% across the suite.",
        "invented_contributor_count": "There are 99 contributors active this month.",
        "authentic_loc": "The repo has 18,432 LOC.",
        "authentic_semver": "Pinned at pygit2 1.19.2.",
        "abbreviation_split": "Eg. The agent invented 73. The next sentence is fine.",
        "every_file_smuggling": "Every file passes lint.",
    }
