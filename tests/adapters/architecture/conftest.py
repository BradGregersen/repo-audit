"""Shared fixtures for the Phase-14 architecture adapter tests (Plan 14-01).

Analog of ``tests/adapters/cicd/conftest.py``. Provides:

  * :func:`fake_js_repo` — a factory building a tmp JS repo with a CONFIGURABLE
    subset of two architecture surfaces: a real 2-file circular dependency
    (``src/a.js`` <-> ``src/b.js``, CommonJS ``require`` cycle) and a duplicated
    pair (``src/dup_b.js`` / ``src/dup_c.js`` sharing a ~20-line block). The
    circular + duplicate flags toggle each surface so collector tests can drive
    the present×absent matrix without re-authoring repos. ``with_config=True``
    drops a minimal ``.dependency-cruiser.json`` so the depcruise "repo has its
    own config -> no shipped ``--config``" path can be exercised.
  * :func:`fake_repo_on_disk` — a git-SEEDED tmp repo (verbatim from the cicd
    analog) so the later Plan-04 ``run_scan`` wiring test can run the real
    pipeline (its pre-flight git snapshot + post-flight tripwire need a real git
    repo).
  * :func:`load_json` — a loader (the ``load_sarif`` shape) that ``json.loads`` a
    recorded ``fixtures/{tool}/sample.json`` document by tool name. Mirrors
    ``tests/adapters/sarif/conftest.py::load_sarif``.

No production module is imported here — the architecture adapter package is a
Wave-0 skeleton; the per-collector tests gate on their target modules via
``importorskip`` / ``skipif`` and SKIP cleanly until Plans 02/03/04 land.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Callable

import pytest

# The Plan 14-01 REAL-recorded JSON fixtures live alongside this conftest.
_ARCH_FIXTURES = Path(__file__).parent / "fixtures"

# A representative ~20-line duplicated block (>= --min-lines 5, >= --min-tokens 50
# once jscpd tokenizes it) so a real jscpd run on fake_js_repo(duplicate=True)
# would detect a clone. Kept in one place so both duplicate files stay identical.
_DUP_BLOCK = """\
function processOrders(orders, taxRate, discountThreshold) {
  let subtotal = 0;
  let itemCount = 0;
  for (const order of orders) {
    for (const line of order.lines) {
      subtotal += line.price * line.quantity;
      itemCount += line.quantity;
    }
  }
  let discount = 0;
  if (subtotal > discountThreshold) {
    discount = subtotal * 0.1;
  }
  const taxable = subtotal - discount;
  const tax = taxable * taxRate;
  const total = taxable + tax;
  return { subtotal, discount, tax, total, itemCount };
}
"""

# A minimal zero-config-repo ruleset (RESEARCH Code Examples) so the
# depcruise "repo HAS its own config -> no shipped --config" path is testable.
_MINIMAL_DC_CONFIG = {
    "forbidden": [
        {
            "name": "no-circular",
            "comment": "circular dependency chain",
            "severity": "error",
            "from": {},
            "to": {"circular": True},
        }
    ]
}


# --------------------------------------------------------------------------- #
# load_json — recorded-fixture loader (load_sarif shape)
# --------------------------------------------------------------------------- #
@pytest.fixture
def load_json() -> Callable[[str], dict[str, Any]]:
    """Return a loader for the frozen ``fixtures/{tool}/sample.json`` document.

    Raises FileNotFoundError with a clear message if the fixture is missing so a
    misnamed tool fails loud rather than returning an empty doc. Mirrors
    ``tests/adapters/sarif/conftest.py::load_sarif``.
    """

    def _load(tool: str) -> dict[str, Any]:
        path = _ARCH_FIXTURES / tool / "sample.json"
        if not path.exists():
            raise FileNotFoundError(
                f"load_json({tool!r}) — recorded fixture missing: {path}"
            )
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)

    return _load


# --------------------------------------------------------------------------- #
# fake_js_repo — configurable architecture-surface factory
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_js_repo(tmp_path) -> Callable[..., Path]:
    """Factory building a tmp JS repo with a configurable architecture surface.

    Usage::

        repo = fake_js_repo(circular=True, duplicate=True, with_config=False)

    Flags:
      * ``circular``    -> ``src/a.js`` <-> ``src/b.js`` real CommonJS require cycle
      * ``duplicate``   -> ``src/dup_b.js`` / ``src/dup_c.js`` share ``_DUP_BLOCK``
      * ``with_config`` -> drop a minimal ``.dependency-cruiser.json`` at the root
                           (the "repo brings its own config" case)
      * ``package_json`` (default True) -> a minimal ``package.json`` so the repo
                           reads as a JS/Node stack

    Returns the repo root :class:`Path`. Each call gets its own subdirectory so a
    test may build several distinct repos.
    """
    counter = {"n": 0}

    def _factory(
        *,
        circular: bool = False,
        duplicate: bool = False,
        with_config: bool = False,
        package_json: bool = True,
    ) -> Path:
        counter["n"] += 1
        repo = tmp_path / f"js_repo_{counter['n']}"
        src = repo / "src"
        src.mkdir(parents=True, exist_ok=True)

        if package_json:
            (repo / "package.json").write_text(
                '{\n  "name": "fake-js-repo",\n  "version": "0.0.0"\n}\n',
                encoding="utf-8",
            )
        if circular:
            (src / "a.js").write_text(
                "const b = require('./b');\n"
                "module.exports = function a() { return b(); };\n",
                encoding="utf-8",
            )
            (src / "b.js").write_text(
                "const a = require('./a');\n"
                "module.exports = function b() { return a(); };\n",
                encoding="utf-8",
            )
        if duplicate:
            (src / "dup_b.js").write_text(
                _DUP_BLOCK + "\nmodule.exports = { processOrders, tag: 'b' };\n",
                encoding="utf-8",
            )
            (src / "dup_c.js").write_text(
                _DUP_BLOCK + "\nmodule.exports = { processOrders, tag: 'c' };\n",
                encoding="utf-8",
            )
        if with_config:
            (repo / ".dependency-cruiser.json").write_text(
                json.dumps(_MINIMAL_DC_CONFIG, indent=2) + "\n",
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

    Verbatim from ``tests/adapters/cicd/conftest.py::fake_repo_on_disk`` (which
    in turn mirrors ``tests/orchestration/test_scan_runner_sast.py``).
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
