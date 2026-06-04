"""CICD-01 workflows-collector contract stubs (Plan 13-01 Task 3; Wave-1 gated).

The opening ``pytest.importorskip`` keeps this module SKIPPED until the Wave-1
implementation ``repo_audit.adapters.cicd.workflows`` lands (the 03-01b
SKIPPED->ACTIVE-on-landing discipline), at which point these contract assertions
activate automatically. The function NAMES match the 13-VALIDATION.md Per-Task
Verification Map (``test_zizmor_sarif`` / ``test_actionlint_json`` /
``test_zizmor_unavailable``) and must NOT be renamed.

Do NOT create ``workflows.py`` from this plan — that flips the importorskip from
SKIP to a failing collection.
"""
from __future__ import annotations

import pytest

workflows = pytest.importorskip(
    "repo_audit.adapters.cicd.workflows",
    reason="Wave 1 (Plan 02) not yet landed — cicd.workflows missing",
)


def test_zizmor_sarif(fake_cicd_repo, zizmor_sarif_path, load_sarif, monkeypatch):
    """zizmor recorded SARIF -> findings, dimension=security, every confidence=candidate.

    Wave-1 contract outline (activates when workflows.py lands):
      - feed the recorded zizmor SARIF as the tool's stdout (monkeypatch run_tool
        / pytest-subprocess) returncode 0
      - call workflows.collect_zizmor over a repo WITH .github/workflows
      - assert len(findings) >= 1
      - assert all f.source_tool == "zizmor"
      - assert all f.dimension == "security"
      - assert all f.evidence_type == "static"
      - assert all f.confidence == "candidate"   (D-06-03 cap; never candidate+critical)
    """
    raise NotImplementedError("Wave-1 collect_zizmor contract — fill when workflows.py lands")


def test_actionlint_json(fake_cicd_repo, actionlint_json_path, monkeypatch):
    """actionlint JSON fixture -> findings, dimension=process, severity=minor.

    Wave-1 contract outline:
      - feed the recorded actionlint JSON (sample.json) as stdout, returncode 1
        (actionlint exits 1 on findings — gate on PARSE not returncode)
      - call workflows.collect_actionlint over a repo WITH .github/workflows
      - assert len(findings) == 3   (the 3 fixture entries: shellcheck/action/expression)
      - assert all f.dimension == "process"
      - assert all f.severity == "minor"
      - assert all f.source_tool == "actionlint"
      - assert all f.confidence == "candidate"
      - assert {f.rule_id for f in findings} == {"shellcheck", "action", "expression"}
    """
    raise NotImplementedError("Wave-1 collect_actionlint contract — fill when workflows.py lands")


def test_zizmor_unavailable(fake_cicd_repo, monkeypatch):
    """resolve_tool -> None gives status=='unavailable', no raise, no hang.

    Wave-1 contract outline:
      - monkeypatch.setattr(workflows, "resolve_tool", lambda *a, **k: None)
      - call workflows.collect_zizmor over a repo WITH .github/workflows
      - assert result.status == "unavailable"   (tool absent, NOT no-files)
      - assert the collector did not raise
    """
    raise NotImplementedError("Wave-1 collect_zizmor unavailable contract — fill when workflows.py lands")
