"""Shared fixtures for the Phase-13 cicd adapter tests (Plan 13-01, Task 3).

Provides:

  * :func:`fake_cicd_repo` — a factory building a tmp repo with a CONFIGURABLE
    subset of the three CI/CD surfaces (``.github/workflows/ci.yml``, a
    ``Dockerfile``, a ``main.tf``) so collector + composite tests can drive the
    present×absent matrix without re-authoring repos.
  * :func:`fake_repo_on_disk` — a git-SEEDED tmp repo (mirrors
    ``test_scan_runner_sast.py``) so the Plan-04 ``run_scan`` wiring test can run
    the real pipeline (its pre-flight git snapshot + post-flight tripwire need a
    real git repo).
  * recorded-fixture PATH helpers reusing the Phase-6 SARIF corpus
    (``zizmor_sarif_path`` / ``hadolint_sarif_path`` / ``checkov_sarif_path``)
    and the NEW actionlint JSON fixture (``actionlint_json_path``). No test
    re-records a SARIF fixture that already exists.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable

import pytest

# Phase-6 recorded SARIF corpus (reused, never re-recorded).
_SARIF_FIXTURES = Path(__file__).parents[1] / "sarif" / "fixtures"
# The NEW Phase-13 actionlint JSON fixture (Plan 13-01 Task 1).
_CICD_FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# Recorded-fixture PATH helpers (Phase-6 SARIF reuse + new actionlint JSON)
# --------------------------------------------------------------------------- #
@pytest.fixture
def zizmor_sarif_path() -> Path:
    """Path to the recorded zizmor SARIF fixture (Phase 6)."""
    return _SARIF_FIXTURES / "zizmor" / "sample.sarif"


@pytest.fixture
def hadolint_sarif_path() -> Path:
    """Path to the recorded hadolint SARIF fixture (Phase 6)."""
    return _SARIF_FIXTURES / "hadolint" / "sample.sarif"


@pytest.fixture
def checkov_sarif_path() -> Path:
    """Path to the recorded checkov SARIF fixture (Phase 6)."""
    return _SARIF_FIXTURES / "checkov" / "sample.sarif"


@pytest.fixture
def actionlint_json_path() -> Path:
    """Path to the NEW recorded actionlint JSON fixture (Plan 13-01, A1)."""
    return _CICD_FIXTURES / "actionlint" / "sample.json"


@pytest.fixture
def load_sarif() -> Callable[[Path], dict]:
    """Return a helper that ``json.loads`` a recorded SARIF/JSON fixture path."""

    def _load(path: Path) -> dict:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    return _load


# --------------------------------------------------------------------------- #
# fake_cicd_repo — configurable CI/CD surface factory
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_cicd_repo(tmp_path) -> Callable[..., Path]:
    """Factory building a tmp repo with a configurable subset of CI/CD surfaces.

    Usage::

        repo = fake_cicd_repo(workflows=True, dockerfile=False, iac=False)

    Each flag toggles one surface:
      * ``workflows`` -> ``.github/workflows/ci.yml``
      * ``dockerfile`` -> ``Dockerfile``
      * ``iac`` -> ``main.tf``

    Returns the repo root :class:`Path`. Each call gets its own subdirectory so a
    test may build several distinct repos.
    """
    counter = {"n": 0}

    def _factory(
        *, workflows: bool = False, dockerfile: bool = False, iac: bool = False
    ) -> Path:
        counter["n"] += 1
        repo = tmp_path / f"cicd_repo_{counter['n']}"
        repo.mkdir(parents=True, exist_ok=True)

        if workflows:
            wf = repo / ".github" / "workflows"
            wf.mkdir(parents=True, exist_ok=True)
            (wf / "ci.yml").write_text(
                "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v1\n"
                "      - run: echo $UNQUOTED\n",
                encoding="utf-8",
            )
        if dockerfile:
            (repo / "Dockerfile").write_text(
                "FROM python:3.12\nRUN pip install requests\nCMD python app.py\n",
                encoding="utf-8",
            )
        if iac:
            (repo / "main.tf").write_text(
                'resource "aws_s3_bucket" "b" {\n  bucket = "example"\n}\n',
                encoding="utf-8",
            )
        return repo

    return _factory


# --------------------------------------------------------------------------- #
# fake_repo_on_disk — git-seeded repo for the run_scan wiring test
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_repo_on_disk(tmp_path) -> Path:
    """A minimal git repo so run_scan's git snapshot / post-flight checks work.

    Mirrors ``tests/orchestration/test_scan_runner_sast.py::fake_repo_on_disk``.
    """
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    (tmp_path / "README.md").write_text("# fake\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path),
            "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-q", "-m", "init",
        ],
        check=True,
    )
    return tmp_path
