"""Phase 2 collector-test fixtures.

The Phase 1 conftest fixtures (fake_repo, polyglot_repo, synthetic_secret,
runner) are inherited via pytest's fixture-inheritance rules.
"""
from __future__ import annotations
from datetime import date

import pytest


@pytest.fixture
def synthetic_partial_scan_report():
    """A ScanReport with meta.partial=True and empty findings/ledger.

    Used by tests/collectors/test_completion_honesty.py to assert that
    the template's static prose passes completion_honesty_lint when
    partial=True (Pitfall 5 mitigation regression).
    """
    from repo_audit.schema.report import ReportMeta, ScanReport
    from repo_audit.schema.scope_ledger import ScopeLedger
    meta = ReportMeta(
        repo_slug="partial-test",
        commit_sha="0" * 40,
        scan_date=date(2026, 5, 28),
        tool_version="0.1.0",
        partial=True,
    )
    return ScanReport(schema_version="1", meta=meta, findings=[], scope_ledger=ScopeLedger())


@pytest.fixture
def skipped_dir_repo(tmp_path):
    """A repo with one valid file at root + one inside node_modules/ (skipped).

    Walker tests use this to assert auto-logging of (path, 'dependencies').
    """
    repo = tmp_path / "skipped-dir-repo"
    repo.mkdir()
    (repo / "src.py").write_text("print('hi')\n", encoding="utf-8")
    nm = repo / "node_modules"
    nm.mkdir()
    (nm / "ignored.js").write_text("// ignored\n", encoding="utf-8")
    return repo
