"""Wave 0 stub for D-56.

Each test in this file flips from SKIPPED to ACTIVE automatically once the
module it importorskips on lands in Wave N. Do NOT remove importorskip in
this Wave 0 task — Waves 2-4 own the implementation; this task only pins
contract names. The importorskip targets the `repo_audit.agent` package;
once it lands (with prompts/scan_report.md.j2 packaged inside it), these tests
flip ACTIVE.

RESEARCH §"Validation Architecture (Nyquist)" maps these test names:
- test_prompt_template_packaged                    (D-56 — scan_report.md.j2 packaged)
- test_prompt_template_has_eight_sections          (D-56 — boundary/7-dim taxonomy/tool-call
                                                     discipline/faithfulness contract/SAFE-06/
                                                     SAFE-07/emit_report schema/scope-ledger awareness)
- test_prompt_template_renders_with_detected_stack_var (D-56 — renders with detected_stack var)
"""
from __future__ import annotations

import pytest

_mod = pytest.importorskip(
    "repo_audit.agent",
    reason="optional module repo_audit.agent not importable — feature not present in this build, or the install is incomplete",
)


def test_prompt_template_packaged():
    """D-56: the prompts directory contains scan_report.md.j2."""
    pass


def test_prompt_template_has_eight_sections():
    """D-56: the prompt template has the eight required sections."""
    pass


def test_prompt_template_renders_with_detected_stack_var():
    """D-56: the prompt template renders with the detected_stack variable."""
    pass
