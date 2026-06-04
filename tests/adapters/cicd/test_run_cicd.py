"""run_cicd composite-envelope contract stubs (Plan 13-01 Task 3; Wave-2 gated).

Gated on the PACKAGE ATTRIBUTE ``cicd.run_cicd`` (Plan 04 owns the composite),
not an importable submodule — so a module-level ``skipif`` is the right discipline
(mirrors Phase-4 ``test_cli_no_agent_flag``). The functions activate the instant
Plan 04 adds ``run_cicd`` to the package namespace.

Function names (``test_no_surface_all_unavailable`` / ``test_tool_absent_degrades`` /
``test_tool_timeout_degrades``) match 13-VALIDATION.md and must NOT be renamed.
"""
from __future__ import annotations

import pytest

import repo_audit.adapters.cicd as cicd

pytestmark = pytest.mark.skipif(
    not hasattr(cicd, "run_cicd"),
    reason="Wave 2 (Plan 04) not yet landed — cicd.run_cicd missing",
)


def test_no_surface_all_unavailable(fake_cicd_repo):
    """No workflows/Dockerfile/IaC -> all sub-results unavailable/not_applicable; never raises.

    Wave-2 contract outline (activates when run_cicd lands):
      - build a repo with NO CI/CD surface (fake_cicd_repo() all-False)
      - result = cicd.run_cicd(repo, base_env={})
      - assert the composite did not raise
      - assert result.findings == []
      - assert result.status in {"not_applicable", "unavailable", "ok"} with a
        disclosed ledger note PER absent surface (zizmor/actionlint/hadolint/checkov)
      - the no-files case is NOT-applicable: it must NOT roll up to a partial-
        flipping status (D-13-05).
    """
    raise NotImplementedError("Wave-2 run_cicd no-surface contract — fill when run_cicd lands")


def test_tool_absent_degrades(fake_cicd_repo, monkeypatch):
    """A tool absent (EXEC_FAILED / resolve_tool None) -> 'unavailable' with a clear reason.

    Wave-2 contract outline:
      - build a repo WITH workflows so zizmor/actionlint are applicable
      - force the tool binary absent (monkeypatch the sub-collector's resolve_tool
        -> None, or run_tool -> EXEC_FAILED sentinel)
      - result = cicd.run_cicd(repo, base_env={})
      - assert result did not raise
      - assert a ledger_note discloses the tool-absent reason ("not found" /
        "could not be executed"), DISTINCT from the timeout reason below (FND-04)
    """
    raise NotImplementedError("Wave-2 run_cicd tool-absent contract — fill when run_cicd lands")


def test_tool_timeout_degrades(fake_cicd_repo, monkeypatch):
    """A tool timeout (TIMED_OUT) -> 'timeout' with a reason DISTINCT from absent (FND-04).

    Wave-2 contract outline:
      - build a repo WITH workflows
      - force run_tool -> TIMED_OUT sentinel for a sub-collector
      - result = cicd.run_cicd(repo, base_env={})
      - assert result did not raise / hang
      - assert the timeout reason ("exceeded Ns") is DISTINCT from the tool-absent
        reason in test_tool_absent_degrades (the two FND-04 degrade modes never
        collapse into one message)
    """
    raise NotImplementedError("Wave-2 run_cicd timeout contract — fill when run_cicd lands")
