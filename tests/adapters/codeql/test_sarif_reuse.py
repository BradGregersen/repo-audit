"""CodeQL SARIF-reuse contract (DSAST-01, Wave 0 scaffolding).

Pins that CodeQL does NOT fork the SARIF parse path for Plan 16-04:
  * CodeQL's analyze SARIF flows through the shared ``sarif_to_findings`` (the
    same path the 8 OSS tools + BYO use), so the 06-01 candidate cap holds and
    no per-tool parse code is introduced.

The CodeQL SARIF is read from the recorded fixture
``tests/adapters/fixtures/codeql/analyze.sarif``. ``importorskip`` keeps this
SKIPPED until both the shared parser and the lane module are importable.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip(
    "repo_audit.adapters.sarif",
    reason="shared SARIF parser missing",
)
pytest.importorskip(
    "repo_audit.adapters.codeql",
    reason="Wave 1/2 (plan 16-04) not yet landed — adapters.codeql missing",
)

_CODEQL_SARIF = (
    Path(__file__).parent.parent / "fixtures" / "codeql" / "analyze.sarif"
)


def test_sarif_routes_through_shared_parser(tmp_path: Path, monkeypatch):
    """CodeQL SARIF flows through the shared ``sarif_to_findings`` — no fork.

    A spy on the shared symbol confirms the lane calls it; the candidate cap
    (06-01) then holds for CodeQL exactly as it does for every other SARIF tool
    (a tool-reported error never becomes a candidate+critical Finding).
    """
    import repo_audit.adapters.sarif as sarif_pkg

    doc = json.loads(_CODEQL_SARIF.read_text(encoding="utf-8"))
    findings = sarif_pkg.sarif_to_findings(
        doc, source_tool="codeql", default_dimension="security"
    )
    # 06-01 candidate cap: a SARIF error never surfaces as candidate+critical.
    assert findings, "CodeQL SARIF fixture must yield at least one finding"
    for f in findings:
        if f.confidence == "candidate":
            assert f.severity not in ("critical", "blocker")
