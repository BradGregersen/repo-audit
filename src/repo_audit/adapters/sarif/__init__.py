"""Generic SARIF 2.1.0 adapter (FND-01).

The ONE parse path every later security tool (Phases 7–16) plugs into.
Downstream adapters import directly from ``repo_audit.adapters.sarif``:

    from repo_audit.adapters.sarif import sarif_to_findings, map_severity
"""
from repo_audit.adapters.sarif.parser import sarif_to_findings
from repo_audit.adapters.sarif.severity import map_severity

__all__ = ["map_severity", "sarif_to_findings"]
