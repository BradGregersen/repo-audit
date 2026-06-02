"""Phase 3 adapter-test fixtures.

The Phase 1 conftest fixtures (fake_repo, polyglot_repo, synthetic_secret,
runner, fake_repo_with_commits) are inherited via pytest's fixture-inheritance
rules. This module adds adapter-specific fixtures:

- ``recorded_tool_output``  — reads the canned ``(stdout, stderr, returncode)``
  triple from ``tests/adapters/fixtures/{tool}/{scenario}/``. Lets parser tests
  feed real-world tool output shapes into the parsers without invoking a live
  TS toolchain. The shapes were captured live against
  ``/path/to/example-app/node_modules/.bin/`` during 03-RESEARCH and committed
  to git (T-03-13 disposition: accept; review of fixture diffs is the safeguard).

- ``ts_fixture_repo`` / ``ts_fixture_repo_no_lcov`` / ``ts_fixture_repo_stale_lcov``
  — tmp_path git-initialised TypeScript repos with manifests pre-committed.
  Used by the host-independent SC-6 unit test and the integration test stubs.
  The three variants differ only in ``coverage/lcov.info`` presence + mtime so
  the LCOV freshness path (D-43) can be exercised in unit tests.

- ``lcov_path`` — parametrisable fixture returning a path under
  ``tests/adapters/fixtures/lcov/{request.param}.info``.

- ``mock_ts_tools_subprocess`` — factory that registers canned tsc/eslint/knip
  subprocess responses via pytest-subprocess (``fp`` fixture). Enables the
  host-independent SC-6 unit test (checker Blocker 6) — the adapter can run
  end-to-end without ``/path/to/example-app`` being present.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import time
from pathlib import Path
from typing import Callable

import pygit2
import pytest


# --- Module-level constants ------------------------------------------------

FIXTURES_ROOT = Path(__file__).parent / "fixtures"


# --- Recorded tool-output helper ------------------------------------------

@pytest.fixture
def recorded_tool_output() -> Callable[[str, str], tuple[str, str, int]]:
    """Return ``(stdout, stderr, returncode)`` from a recorded fixture.

    Layout: ``tests/adapters/fixtures/{tool}/{scenario}/{stdout,stderr,returncode}.txt``.
    The returncode file MUST contain a single integer line.

    Usage::

        def test_x(recorded_tool_output):
            stdout, stderr, rc = recorded_tool_output("tsc", "errors")
            result = parse(InvocationResult(stdout=stdout, stderr=stderr, returncode=rc))

    Raises ``FileNotFoundError`` with a clear "fixture missing" message if any
    of the three files is absent so misnamed scenarios fail loud rather than
    silently returning empty strings.
    """

    def _read(tool: str, scenario: str) -> tuple[str, str, int]:
        base = FIXTURES_ROOT / tool / scenario
        stdout_p = base / "stdout.txt"
        stderr_p = base / "stderr.txt"
        rc_p = base / "returncode.txt"
        missing = [str(p) for p in (stdout_p, stderr_p, rc_p) if not p.exists()]
        if missing:
            raise FileNotFoundError(
                f"recorded_tool_output({tool!r}, {scenario!r}) — fixture missing: {missing}"
            )
        stdout = stdout_p.read_text(encoding="utf-8")
        stderr = stderr_p.read_text(encoding="utf-8")
        rc_raw = rc_p.read_text(encoding="utf-8").strip()
        return stdout, stderr, int(rc_raw)

    return _read


# --- Fixture-repo factories ------------------------------------------------

_TS_MANIFESTS: dict[str, str] = {
    "package.json": json.dumps(
        {
            "name": "ts-fixture",
            "type": "module",
            "version": "0.0.0",
            "devDependencies": {"typescript": "^5.0.0"},
        },
        indent=2,
    ),
    "tsconfig.json": json.dumps(
        {"compilerOptions": {"strict": True, "noEmit": True}},
        indent=2,
    ),
    # Minimal flat config — eslint 9.x doesn't crash on an empty array.
    "eslint.config.js": "export default [];\n",
    # Empty knip config — knip 6.x accepts {}.
    "knip.json": "{}\n",
    # A source file so tsc has something to type-check.
    "src/index.ts": "export const x: number = 1;\n",
}


def _seed_ts_repo(
    repo_path: Path,
    *,
    lcov: str | None,
    lcov_mtime_offset_seconds: float | None,
) -> Path:
    """Build a TypeScript fixture repo with one initial commit.

    Args:
        repo_path: target directory (must not already exist).
        lcov: name (without extension) under ``fixtures/lcov/`` to copy as
            ``coverage/lcov.info`` — or ``None`` to skip lcov entirely.
        lcov_mtime_offset_seconds: relative-to-now mtime for the lcov file
            (negative = past). Ignored when ``lcov is None``.
    """
    repo_path.mkdir(parents=True, exist_ok=True)
    repo = pygit2.init_repository(str(repo_path), bare=False)
    for rel, contents in _TS_MANIFESTS.items():
        f = repo_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(contents, encoding="utf-8")
    if lcov is not None:
        src = FIXTURES_ROOT / "lcov" / f"{lcov}.info"
        dst = repo_path / "coverage" / "lcov.info"
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    # Commit everything currently on disk so a follow-up mtime touch (lcov
    # staleness) does not show up as an uncommitted change.
    repo.index.add_all()
    repo.index.write()
    tree = repo.index.write_tree()
    ts = int(_dt.datetime(2026, 5, 28, 12, 0, 0).timestamp())
    sig = pygit2.Signature("ts-fixture", "ts-fixture@example.com", ts, 0)
    repo.create_commit("HEAD", sig, sig, "init", tree, [])
    # Apply the mtime AFTER the commit so the offset is honoured at test time.
    if lcov is not None and lcov_mtime_offset_seconds is not None:
        lcov_path = repo_path / "coverage" / "lcov.info"
        t = time.time() + lcov_mtime_offset_seconds
        os.utime(lcov_path, (t, t))
    return repo_path


@pytest.fixture
def ts_fixture_repo(tmp_path) -> Path:
    """A git-initialised TS repo with a FRESH ``coverage/lcov.info``.

    The lcov mtime is set to ``time.time() - 60`` so the D-43 freshness gate
    (``> 24h`` ⇒ stale) passes deterministically across slow runners.
    """
    return _seed_ts_repo(
        tmp_path / "ts-fixture",
        lcov="fresh",
        lcov_mtime_offset_seconds=-60.0,
    )


@pytest.fixture
def ts_fixture_repo_no_lcov(tmp_path) -> Path:
    """A git-initialised TS repo with NO ``coverage/lcov.info``.

    D-44 / COV-04: parser must emit an ``unavailable`` Finding.
    """
    return _seed_ts_repo(
        tmp_path / "ts-fixture-no-lcov",
        lcov=None,
        lcov_mtime_offset_seconds=None,
    )


@pytest.fixture
def ts_fixture_repo_stale_lcov(tmp_path) -> Path:
    """A git-initialised TS repo whose ``coverage/lcov.info`` is 25h old.

    Drives D-43: staleness threshold is 24h, so 25h ⇒ unavailable.
    """
    return _seed_ts_repo(
        tmp_path / "ts-fixture-stale-lcov",
        lcov="stale",
        lcov_mtime_offset_seconds=-(25.0 * 3600.0),
    )


@pytest.fixture
def lcov_path(request) -> Path:
    """Return ``FIXTURES_ROOT / 'lcov' / f'{request.param}.info'``.

    Parametrise with one of: ``"fresh"``, ``"stale"``, ``"malformed"``.

    Usage::

        @pytest.mark.parametrize("lcov_path", ["fresh", "malformed"], indirect=True)
        def test_lcov(lcov_path):
            ...
    """
    name = getattr(request, "param", "fresh")
    return FIXTURES_ROOT / "lcov" / f"{name}.info"


# --- Plan 03-05 integration-only fixture: symlinked dogfood toolchain ----


_DOGFOOD_NODE_MODULES = Path("/path/to/example-app/node_modules")


@pytest.fixture
def ts_fixture_repo_with_tools(tmp_path) -> Path:
    """Integration-only: tmp_path TS repo + symlinked dogfood node_modules.

    Skips if ``/path/to/example-app/node_modules`` is not present (CI without
    the dogfood checkout). The symlink makes
    ``tmp_path/node_modules/.bin/{tsc,eslint,knip}`` resolve transparently
    so the adapter's ``resolve_tool`` walk-up finds real binaries without
    the cost of a per-test ``npm install``.

    The symlink also means tests should NOT mutate ``tmp_path/node_modules/``
    (would write to the dogfood repo). Adapters in this codebase only READ
    from node_modules, so the contract is naturally honored.
    """
    if not _DOGFOOD_NODE_MODULES.is_dir():
        pytest.skip(
            f"dogfood node_modules not present at {_DOGFOOD_NODE_MODULES}"
        )
    repo = tmp_path / "ts-with-tools"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"name": "fixture", "type": "module", '
        '"devDependencies": {"typescript": "*"}}\n',
        encoding="utf-8",
    )
    (repo / "tsconfig.json").write_text(
        '{"compilerOptions": {"strict": true, "noEmit": true, '
        '"module": "esnext", "target": "esnext", '
        '"moduleResolution": "node"}}\n',
        encoding="utf-8",
    )
    (repo / "eslint.config.js").write_text(
        "export default [];\n", encoding="utf-8",
    )
    os.symlink(_DOGFOOD_NODE_MODULES, repo / "node_modules")
    # Make it a real git repo so post-flight git_status works.
    pygit2.init_repository(str(repo), bare=False)
    r = pygit2.Repository(str(repo))
    r.index.add_all()
    r.index.write()
    tree = r.index.write_tree()
    ts = int(_dt.datetime(2026, 5, 28, 12, 0, 0).timestamp())
    sig = pygit2.Signature("test", "test@example.com", ts, 0)
    r.create_commit("HEAD", sig, sig, "init", tree, [])
    return repo


# --- pytest-subprocess factory (checker Blocker 6 enabler) ---------------

@pytest.fixture
def mock_ts_tools_subprocess(fp, recorded_tool_output):
    """Register canned subprocess outputs for tsc/eslint/knip via pytest-subprocess.

    Returns a CALLABLE — callers select per-tool scenarios at use time::

        def test_x(tmp_path, mock_ts_tools_subprocess):
            mock_ts_tools_subprocess(tsc="clean", eslint="clean", knip="clean")
            # any subsequent subprocess.run(...) inside the adapter under test
            # is intercepted by pytest-subprocess and returns the canned triple.

    Why ``fp.any()`` matchers + ``occurrences=10``:
        The adapter (Wave 2) decides its own argv (project-local resolution +
        cache-redirection env). Pinning exact argv here would couple the
        fixture to Wave 2 implementation detail. ``fp.any()`` matches any
        command, and the wildcard registers ONE response per scenario; the
        ``occurrences=10`` allowance tolerates the adapter calling its tools
        once per invocation in addition to any defensive double-check.

    Important: each call to the inner ``_register`` registers THREE
    wildcards in registration order. pytest-subprocess matches first
    registration first, so we register in the order tsc → eslint → knip and
    expect the adapter to invoke its tools in that same order. If a Wave 2
    refactor reorders invocation, this fixture's contract needs updating.
    """

    def _register(*, tsc: str = "clean", eslint: str = "clean", knip: str = "clean") -> None:
        for tool, scenario in (("tsc", tsc), ("eslint", eslint), ("knip", knip)):
            stdout, stderr, returncode = recorded_tool_output(tool, scenario)
            fp.register(
                [fp.any()],
                stdout=stdout,
                stderr=stderr,
                returncode=returncode,
                occurrences=10,
            )

    return _register


# --- Phase 9 (Mobile Pentest) fixtures -------------------------------------


@pytest.fixture
def expo_android_repo(tmp_path) -> Path:
    """A synthetic Expo->Android repo built under ``tmp_path``.

    Delegates to the Plan 09-00 factory
    (``tests/adapters/fixtures/mobile/expo_repo_factory.make_expo_android_repo``)
    which seeds the secret-leak surfaces the Phase 9 Tier-2 bundled-secrets pass
    (Plan 02) and the mobsfscan integration run (Plan 01) exercise: a hardcoded
    ``service_role`` JWT (``app.config.js``), the PUBLIC anon key (``.env``), an
    ``sb_secret_`` value (``eas.json``), a native ``strings.xml`` api_key, and a
    secret-free client ``Login.tsx``. All secrets are synthetic (PROVENANCE.md).

    Imported lazily (inside the fixture body) so the conftest has no import-time
    dependency on the fixtures package.
    """
    import sys

    mobile_dir = FIXTURES_ROOT / "mobile"
    if str(mobile_dir) not in sys.path:
        sys.path.insert(0, str(mobile_dir))
    from expo_repo_factory import make_expo_android_repo  # noqa: E402

    return make_expo_android_repo(tmp_path / "expo-fixture")


@pytest.fixture
def mobsf_report_json() -> dict:
    """The hand-authored MobSF ``StaticAnalyzerAndroid`` ``report_json`` fixture (A4).

    Returns the parsed JSON document from
    ``tests/adapters/fixtures/mobile/mobsf_report_json.json`` — the Tier-3a
    mapper (Plan 03) consumes its ``secrets`` / ``possible_secrets`` / ``findings``
    keys. Secrets inside are synthetic (PROVENANCE.md, A4: re-record live when the
    MobSF Docker image is pulled).
    """
    path = FIXTURES_ROOT / "mobile" / "mobsf_report_json.json"
    return json.loads(path.read_text(encoding="utf-8"))


# --- Phase 10 (SAST — Semgrep) fixtures ------------------------------------


@pytest.fixture
def sast_vuln_repo(tmp_path) -> Path:
    """A synthetic vulnerable Expo/RN repo built under ``tmp_path``.

    Delegates to the Plan 10-00 factory
    (``tests/adapters/fixtures/sast/vuln_repo_factory.make_sast_vuln_repo``)
    which seeds an obvious OS-command-injection (``src/vuln.py``, OWASP-A03), a
    benign React surface (``src/component.tsx``), a ``package.json`` declaring
    react/react-native/expo (so the detector selects ``p/react``), and a ``.env``
    carrying the SYNTHETIC public anon key (the key the SAST-03 drop must NOT
    surface as a leak). The Wave-3 ``-m integration`` live Semgrep run scans it.
    All secrets are synthetic (PROVENANCE.md).

    Imported lazily (inside the fixture body) so the conftest has no import-time
    dependency on the fixtures package.
    """
    import sys

    sast_dir = FIXTURES_ROOT / "sast"
    if str(sast_dir) not in sys.path:
        sys.path.insert(0, str(sast_dir))
    from vuln_repo_factory import make_sast_vuln_repo  # noqa: E402

    return make_sast_vuln_repo(tmp_path / "sast-vuln-fixture")


@pytest.fixture
def owasp_sarif() -> dict:
    """The hand-authored Semgrep owasp-top-ten SARIF fixture (Pitfall-1 shape).

    Returns the parsed JSON from
    ``tests/adapters/fixtures/sast/owasp_top_ten.sarif`` — ``result.level=null``
    + ``rule.defaultConfiguration.level`` (error/warning) + OWASP/CWE tags, no
    ``security-severity``. Pins the severity-collapse the D-10-03 parser fix
    (Wave 1) repairs. Secrets-free.
    """
    path = FIXTURES_ROOT / "sast" / "owasp_top_ten.sarif"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def secrets_anon_sarif() -> dict:
    """The hand-authored Semgrep ``p/secrets`` SARIF fixture (SAST-03 shape).

    Returns the parsed JSON from
    ``tests/adapters/fixtures/sast/secrets_anon.sarif`` — two results: a PUBLIC
    anon key (matches ``footguns._ANON_ALLOWLIST``, must be dropped) and a
    genuine ``service_role`` secret (must be kept + redacted). All values are
    synthetic (PROVENANCE.md).
    """
    path = FIXTURES_ROOT / "sast" / "secrets_anon.sarif"
    return json.loads(path.read_text(encoding="utf-8"))
