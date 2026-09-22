"""CICD-01 workflows-collector contract (Plan 13-02, Wave-1).

The opening ``pytest.importorskip`` keeps this module SKIPPED until the Wave-1
implementation ``repo_audit.adapters.cicd.workflows`` lands (the 03-01b
SKIPPED->ACTIVE-on-landing discipline), at which point these contract assertions
activate automatically. The function NAMES match the 13-VALIDATION.md Per-Task
Verification Map (``test_zizmor_sarif`` / ``test_actionlint_json`` /
``test_zizmor_unavailable``) and must NOT be renamed.

zizmor stdout is fed via ``pytest-subprocess`` (``fp``) as canned SARIF; the
absent-binary path monkeypatches ``workflows.resolve_tool`` to ``None``. Both
collectors gate on PARSE success, never on returncode (zizmor exits 0 always;
actionlint exits 1 on findings) — see Pitfall 6.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

workflows = pytest.importorskip(
    "repo_audit.adapters.cicd.workflows",
    reason="optional module repo_audit.adapters.cicd.workflows not importable — feature not present in this build, or the install is incomplete",
)

# A fake resolved-binary path so the recorded-fixture parse tests are HERMETIC —
# they exercise the parse path via pytest-subprocess (``fp``) regardless of
# whether zizmor/actionlint happen to be installed on the test host.
_FAKE_BIN = Path("/usr/bin/__cicd_tool__")


def _stub_resolve(monkeypatch):
    monkeypatch.setattr(
        workflows, "resolve_tool", lambda *a, **k: _FAKE_BIN, raising=False
    )


def test_zizmor_sarif(fake_cicd_repo, zizmor_sarif_path, load_sarif, fp, monkeypatch):
    """zizmor recorded SARIF -> findings, dimension=security, every confidence=candidate.

    Feed the recorded zizmor SARIF as the tool's stdout (pytest-subprocess) with
    returncode 0, call collect_zizmor over a repo WITH .github/workflows, and
    assert the CICD-01 security-finding contract.
    """
    repo = fake_cicd_repo(workflows=True)
    _stub_resolve(monkeypatch)
    sarif_bytes = json.dumps(load_sarif(zizmor_sarif_path))
    fp.register([fp.any()], stdout=sarif_bytes, returncode=0, occurrences=10)

    result = workflows.collect_zizmor(repo, env={})
    findings = result.findings

    assert result.status == "ok"
    assert len(findings) >= 1
    assert all(f.source_tool == "zizmor" for f in findings)
    assert all(f.dimension == "security" for f in findings)
    assert all(f.evidence_type == "static" for f in findings)
    assert all(f.confidence == "candidate" for f in findings)


def test_zizmor_unavailable(fake_cicd_repo, monkeypatch):
    """resolve_tool -> None gives status=='unavailable', no raise, no hang."""
    repo = fake_cicd_repo(workflows=True)
    monkeypatch.setattr(workflows, "resolve_tool", lambda *a, **k: None, raising=False)

    result = workflows.collect_zizmor(repo, env={})

    assert result.status == "unavailable"
    assert result.findings == []


def test_zizmor_no_workflows(fake_cicd_repo, monkeypatch):
    """No .github/workflows -> unavailable with a 'no workflows' reason, tool NOT invoked."""
    repo = fake_cicd_repo(workflows=False)

    def _boom(*a, **k):  # pragma: no cover - asserts the tool is never resolved
        raise AssertionError("resolve_tool must not be called when no workflows exist")

    monkeypatch.setattr(workflows, "resolve_tool", _boom, raising=False)

    result = workflows.collect_zizmor(repo, env={})

    assert result.status == "unavailable"
    assert "workflow" in result.notes.lower()


def test_zizmor_garbage_stdout(fake_cicd_repo, fp, monkeypatch):
    """Non-JSON stdout -> status='unavailable' (no parseable SARIF), no raise."""
    repo = fake_cicd_repo(workflows=True)
    _stub_resolve(monkeypatch)
    fp.register([fp.any()], stdout="not json at all", returncode=0, occurrences=10)

    result = workflows.collect_zizmor(repo, env={})

    assert result.status == "unavailable"


def test_zizmor_nonzero_exit_but_parseable(
    fake_cicd_repo, zizmor_sarif_path, load_sarif, fp, monkeypatch
):
    """Non-zero exit BUT parseable SARIF -> status='ok' (gate on parse, NOT returncode)."""
    repo = fake_cicd_repo(workflows=True)
    _stub_resolve(monkeypatch)
    sarif_bytes = json.dumps(load_sarif(zizmor_sarif_path))
    fp.register([fp.any()], stdout=sarif_bytes, returncode=14, occurrences=10)

    result = workflows.collect_zizmor(repo, env={})

    assert result.status == "ok"
    assert len(result.findings) >= 1


def test_actionlint_json(fake_cicd_repo, actionlint_json_path, load_sarif, fp, monkeypatch):
    """actionlint JSON fixture -> findings, dimension=process, severity=minor.

    Feed the recorded actionlint JSON (sample.json) as stdout with returncode 1
    (actionlint exits 1 on findings — gate on PARSE not returncode), call
    collect_actionlint over a repo WITH .github/workflows, and assert the
    process-dimension minor-finding contract.
    """
    repo = fake_cicd_repo(workflows=True)
    _stub_resolve(monkeypatch)
    json_bytes = json.dumps(load_sarif(actionlint_json_path))
    fp.register([fp.any()], stdout=json_bytes, returncode=1, occurrences=10)

    result = workflows.collect_actionlint(repo, env={})
    findings = result.findings

    assert result.status == "ok"
    assert len(findings) == 3
    assert all(f.dimension == "process" for f in findings)
    assert all(f.severity == "minor" for f in findings)
    assert all(f.source_tool == "actionlint" for f in findings)
    assert all(f.evidence_type == "static" for f in findings)
    assert all(f.confidence == "candidate" for f in findings)
    assert {f.rule_id for f in findings} == {"shellcheck", "action", "expression"}


def test_actionlint_missing_line(fake_cicd_repo, fp, monkeypatch):
    """An entry without a line -> Finding.line is None and line_range is None (no crash)."""
    repo = fake_cicd_repo(workflows=True)
    _stub_resolve(monkeypatch)
    entry = [
        {
            "message": "no line here",
            "filepath": ".github/workflows/ci.yml",
            "column": 3,
            "kind": "syntax-check",
            "snippet": "x",
        }
    ]
    fp.register([fp.any()], stdout=json.dumps(entry), returncode=1, occurrences=10)

    result = workflows.collect_actionlint(repo, env={})

    assert result.status == "ok"
    assert len(result.findings) == 1
    assert result.findings[0].line is None
    assert result.findings[0].evidence.line_range is None


def test_actionlint_empty_array(fake_cicd_repo, fp, monkeypatch):
    """Empty JSON array -> empty findings list, clean, no raise."""
    repo = fake_cicd_repo(workflows=True)
    _stub_resolve(monkeypatch)
    fp.register([fp.any()], stdout="[]", returncode=0, occurrences=10)

    result = workflows.collect_actionlint(repo, env={})

    assert result.status == "ok"
    assert result.findings == []


def test_actionlint_unavailable(fake_cicd_repo, monkeypatch):
    """resolve_tool -> None gives status=='unavailable', no raise."""
    repo = fake_cicd_repo(workflows=True)
    monkeypatch.setattr(workflows, "resolve_tool", lambda *a, **k: None, raising=False)

    result = workflows.collect_actionlint(repo, env={})

    assert result.status == "unavailable"
    assert result.findings == []


def test_actionlint_no_workflows(fake_cicd_repo):
    """No .github/workflows -> unavailable with a 'no workflows' reason."""
    repo = fake_cicd_repo(workflows=False)

    result = workflows.collect_actionlint(repo, env={})

    assert result.status == "unavailable"
    assert "workflow" in result.notes.lower()


def test_actionlint_malformed_stdout(fake_cicd_repo, fp, monkeypatch):
    """Exit 2 / non-JSON stdout -> status='unavailable', no crash."""
    repo = fake_cicd_repo(workflows=True)
    _stub_resolve(monkeypatch)
    fp.register([fp.any()], stdout="actionlint: bad -format", returncode=2, occurrences=10)

    result = workflows.collect_actionlint(repo, env={})

    assert result.status == "unavailable"
