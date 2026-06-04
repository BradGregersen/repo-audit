"""CICD-02 IaC-collector contract stubs (Plan 13-01 Task 3; Wave-2 gated).

SKIPPED until ``repo_audit.adapters.cicd.iac`` (checkov) lands. Function
names (``test_checkov_framework_scoped`` / ``test_checkov_no_iac_unavailable``)
match 13-VALIDATION.md and must NOT be renamed.
"""
from __future__ import annotations

import pytest

iac = pytest.importorskip(
    "repo_audit.adapters.cicd.iac",
    reason="Wave 2 (Plan 03/04) not yet landed — cicd.iac missing",
)


def test_checkov_framework_scoped(fake_cicd_repo, checkov_sarif_path, load_sarif, monkeypatch):
    """checkov SARIF -> findings; NO rule_id starting CKV_DOCKER_ / CKV_GHA_.

    Wave-2 contract outline (activates when iac.py lands):
      - build a repo WITH IaC (fake_cicd_repo(iac=True))
      - simulate checkov writing results_sarif.sarif into the tempdir, returncode 0
        (--soft-fail), then iac.collect_checkov reads + parses it (Pitfall 4)
      - assert len(findings) >= 1
      - assert all f.dimension == "security"
      - assert all f.source_tool == "checkov"
      - assert all f.confidence == "candidate"
      - assert NO finding.rule_id starts with "CKV_DOCKER_" or "CKV_GHA_"
        (--framework scoping EXCLUDES dockerfile/github_actions — Pitfall 3; a
        leaked rule_id is the double-cover warning sign)
    """
    raise NotImplementedError("Wave-2 collect_checkov framework-scoped contract — fill when iac.py lands")


def test_checkov_no_iac_unavailable(fake_cicd_repo):
    """No IaC config -> status=='unavailable' WITHOUT invoking checkov.

    Wave-2 contract outline:
      - build a repo with NO IaC (fake_cicd_repo() all-False)
      - call iac.collect_checkov
      - assert result.status == "unavailable"
      - assert the notes distinguish "no IaC config present" (NOT-applicable
        degrade) from tool-absent / timeout
      - checkov must NOT be invoked (it is the slowest tool — never run on a
        repo with no Terraform/k8s/CFN)
    """
    raise NotImplementedError("Wave-2 collect_checkov no-iac contract — fill when iac.py lands")
