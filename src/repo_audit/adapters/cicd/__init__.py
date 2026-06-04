"""CI/CD & IaC security adapter package (Phase 13).

A CROSS-STACK adapter (like ``adapters/sast`` / ``adapters/sca`` /
``adapters/supply_chain``): it has no per-stack ``@register_adapter`` entry and
is wired into the pipeline as a dedicated repo-wide ``run_cicd`` step by
``orchestration/scan_runner`` — NOT through the stack-detection registry.

This Wave-0 skeleton ships ONLY the foundation both Wave-1 plans depend on:

  * :mod:`repo_audit.adapters.cicd.detect` — read-only detection-and-degrade
    globs (workflows / Dockerfiles / IaC config), driving the SAFE-08 honest
    ``unavailable`` path (D-13-05).
  * ``adapter.yaml`` — the 4-tool (zizmor / actionlint / hadolint / checkov)
    per-tool ``default_dimension`` + ``severity_map`` + ``timeout_ms`` descriptor,
    loaded under ``ruamel.yaml.YAML(typ='safe')`` (T-03-01).

``run_cicd`` + ``CicdScanResult`` (the never-raising composite envelope) and the
``collect_zizmor`` / ``collect_actionlint`` / ``collect_hadolint`` /
``collect_checkov`` collectors land in Wave-1/Wave-2 plans (Plan 04 owns the
``run_cicd`` composite). They are deliberately NOT defined here — defining a stub
now would collide with Plan 04's ``files_modified`` and flip the importorskip-gated
Wave-1 test stubs from SKIPPED to failing.
"""
from __future__ import annotations
