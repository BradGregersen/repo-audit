"""Cross-stack SCA (dependency-CVE) adapter package (Phase 7).

Unlike ``typescript-node`` this package does NOT call ``@register_adapter``.
SCA is CROSS-STACK: it runs once per repo regardless of the detected stack
(RESEARCH Open Question 1, A1 — RESOLVED). Plan 05 wires :func:`osv.collect_osv`
into ``orchestration/scan_runner.run_scan`` as a dedicated scan step alongside
``run_adapters`` (the way repo-wide collectors run), NOT as a per-stack adapter.

``adapter.yaml`` carries the declarative per-tool ``severity_map`` +
``default_dimension`` (osv -> security, D-06-05), loaded under ruamel.yaml's
safe loader (T-03-01) exactly like the TypeScript adapter.

Wave 1 of this phase (Plan 03) ships:
    * :func:`osv.collect_osv` — invoke osv (sarif + json) via ``run_tool``,
      parse findings through the SINGLE ``sarif_to_findings`` path (FND-01),
      fold native-JSON enrichment on.
    * :mod:`enrich` — the ``(cve, pkg, version)``-keyed enrichment map built
      from osv native JSON (direct/transitive + fix version), never a finding
      source.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

# --- adapter.yaml load (T-03-01 safe-mode) --------------------------------

_ADAPTER_YAML_PATH = Path(__file__).parent / "adapter.yaml"


def _load_adapter_yaml() -> dict[str, Any]:
    """Load ``adapter.yaml`` under ruamel.yaml's safe loader (T-03-01).

    ``YAML(typ='safe')`` refuses ``!!python/object`` / ``!!python/name``
    constructors so a poisoned YAML (future user-overlay scenario) cannot
    execute Python at load time. Mirrors the TypeScript adapter's loader posture
    (greppable as ``test``-able ``YAML(typ="safe")``).
    """
    yaml = YAML(typ="safe")
    with _ADAPTER_YAML_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.load(fh)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"adapter.yaml at {_ADAPTER_YAML_PATH} did not load as a mapping; "
            f"got {type(data).__name__}"
        )
    return data


# Public config dict. ADAPTER_CONFIG is the canonical test-and-consumer name;
# CONFIG is the plan-spec alias (mirrors the TypeScript adapter pair).
ADAPTER_CONFIG: dict[str, Any] = _load_adapter_yaml()
CONFIG: dict[str, Any] = ADAPTER_CONFIG

__all__ = ["ADAPTER_CONFIG", "CONFIG"]
