"""CICD-02 containers-collector contract stubs (Plan 13-01 Task 3; Wave-1 gated).

SKIPPED until ``repo_audit.adapters.cicd.containers`` (hadolint) lands.
Function names (``test_hadolint_perfile`` / ``test_hadolint_no_dockerfile_unavailable``)
match 13-VALIDATION.md and must NOT be renamed.
"""
from __future__ import annotations

import pytest

containers = pytest.importorskip(
    "repo_audit.adapters.cicd.containers",
    reason="Wave 1 (Plan 03) not yet landed — cicd.containers missing",
)


def test_hadolint_perfile(fake_cicd_repo, hadolint_sarif_path, load_sarif, monkeypatch):
    """hadolint SARIF per Dockerfile -> findings; the file is a REAL path, NOT "-".

    Wave-1 contract outline (activates when containers.py lands):
      - build a repo WITH a Dockerfile (fake_cicd_repo(dockerfile=True))
      - feed the recorded hadolint SARIF as stdout, returncode 0 (--no-fail)
      - call containers.collect_hadolint
      - assert len(findings) >= 1
      - assert all f.dimension == "security"
      - assert all f.source_tool == "hadolint"
      - assert all f.confidence == "candidate"
      - assert every finding's file is the real Dockerfile path (NOT "-"):
        hadolint is invoked with the path as argv, never stdin (Pitfall 2), so
        artifactLocation.uri carries the real path.
    """
    raise NotImplementedError("Wave-1 collect_hadolint per-file contract — fill when containers.py lands")


def test_hadolint_no_dockerfile_unavailable(fake_cicd_repo):
    """No Dockerfile -> status=='unavailable' WITHOUT invoking the tool.

    Wave-1 contract outline:
      - build a repo with NO Dockerfile (fake_cicd_repo() defaults all-False)
      - call containers.collect_hadolint
      - assert result.status == "unavailable"
      - assert the notes distinguish "no Dockerfile present" (a NOT-applicable
        degrade) from a tool-absent / timeout reason
      - the tool binary must NOT have been invoked
    """
    raise NotImplementedError("Wave-1 collect_hadolint no-dockerfile contract — fill when containers.py lands")
