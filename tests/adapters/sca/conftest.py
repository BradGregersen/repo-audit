"""Fixtures for the SCA recorded-corpus tests (Plans 03/04).

`load_sca_fixture` reads the frozen `fixtures/{rel}` recording — the real osv
native JSON, grype SARIF, grype JSON, and `grype db status` text frozen by Plan
07-02 against the vendored osv-scanner 2.3.8 + grype 0.112.0 binaries (D-06-13).
The confirmed field paths these fixtures pin live in `fixtures/PROVENANCE.md`;
Plans 03/04 build the enrichment + corroboration logic against THOSE paths, not
against guesses.

This mirrors the Phase-6 SARIF loader (`tests/adapters/sarif/conftest.py::load_sarif`):
a thin recorded-fixture loader that fails loud on a misnamed fixture. `.json` /
`.sarif` recordings are parsed to a dict; anything else (e.g. `db-status.txt`) is
returned as raw text.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

FIXTURES_ROOT = Path(__file__).parent / "fixtures"


@pytest.fixture
def load_sca_fixture() -> Callable[[str], Any]:
    """Return a loader for a frozen `fixtures/{rel}` SCA recording.

    Args (to the returned `_load`):
        rel: fixture path relative to `fixtures/`, e.g.
            ``"osv-scanner/sample.json"``, ``"grype/sample.sarif"``,
            ``"grype/db-status.txt"``.

    Returns:
        A parsed ``dict`` for ``.json`` / ``.sarif`` recordings; raw ``str`` for
        any other extension.

    Raises:
        FileNotFoundError: if the recording is missing — a misnamed fixture fails
            loud rather than silently returning an empty doc.
    """

    def _load(rel: str) -> Any:
        path = FIXTURES_ROOT / rel
        if not path.exists():
            raise FileNotFoundError(
                f"load_sca_fixture({rel!r}) — recorded fixture missing: {path}"
            )
        text = path.read_text(encoding="utf-8")
        return json.loads(text) if rel.endswith((".json", ".sarif")) else text

    return _load
