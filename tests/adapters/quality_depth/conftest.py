"""Shared fixtures for the Phase-15 quality_depth adapter tests (Plan 15-01).

Analog of ``tests/adapters/architecture/conftest.py`` reduced to what Wave 0
needs: path fixtures over the four REAL-recorded / hand-authored offline inputs
the Wave-1 parser tests (axe / lighthouse / eslint-a11y / RN bundle) consume, a
``load_json`` loader (the ``load_sarif`` shape), and a ``write_qd_config`` helper
that drops a ``.repo-audit.yaml`` ``quality_depth:`` block in a tmp repo so
the config override-layering test needs no fixture repo authoring.

No production module is imported here — the quality_depth COLLECTORS are a Wave-0
skeleton; the per-collector tests gate on their target modules via
``importorskip`` and SKIP cleanly until Plans 02/03/04 land. (``config.py`` IS
shipped this plan and is imported directly by ``test_config.py``.)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

# The Plan 15-01 offline fixtures live alongside this conftest.
_QD_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def qd_fixtures_dir() -> Path:
    """Absolute path to the quality_depth fixtures directory."""
    return _QD_FIXTURES


@pytest.fixture
def axe_results_path() -> Path:
    """Path to the canned axe-core results JSON (>=2 violations)."""
    return _QD_FIXTURES / "axe_results.json"


@pytest.fixture
def lighthouse_lhr_path() -> Path:
    """Path to the canned Lighthouse Result (LHR) JSON."""
    return _QD_FIXTURES / "lighthouse_lhr.json"


@pytest.fixture
def eslint_a11y_path() -> Path:
    """Path to the canned ESLint JSON report (jsx-a11y + react-native-a11y)."""
    return _QD_FIXTURES / "eslint_a11y.json"


@pytest.fixture
def rn_bundle_path() -> Path:
    """Path to the canned RN Metro bundle artifact (known byte size)."""
    return _QD_FIXTURES / "index.android.bundle"


@pytest.fixture
def load_json() -> Callable[[str], Any]:
    """``json.loads`` a fixture document by file name (the load_sarif shape)."""

    def _load(name: str) -> Any:
        with (_QD_FIXTURES / name).open(encoding="utf-8") as fh:
            return json.load(fh)

    return _load


@pytest.fixture
def write_qd_config(tmp_path: Path) -> Callable[[str], Path]:
    """Drop a ``.repo-audit.yaml`` with a raw ``quality_depth`` block.

    Returns the tmp repo root so a test can call
    ``read_quality_depth_config(repo)`` against it. The ``block_yaml`` argument is
    the raw YAML body UNDER ``quality_depth:`` (already indented two spaces).
    """

    def _write(block_yaml: str) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir(exist_ok=True)
        (repo / ".repo-audit.yaml").write_text(
            "quality_depth:\n" + block_yaml,
            encoding="utf-8",
        )
        return repo

    return _write
