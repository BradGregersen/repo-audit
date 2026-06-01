"""Fixtures for the SARIF 8-tool recorded-corpus round-trip (FND-01 / SC-1).

`load_sarif(tool)` reads the frozen `fixtures/{tool}/sample.sarif`. `TOOL_CONFIG`
is the per-tool `(default_dimension, severity_map)` table — the ONLY per-tool
difference fed into the single `sarif_to_findings` function. The corpus + its
provenance live in `fixtures/PROVENANCE.md` (D-06-13). This mirrors the Phase 3
recorded-fixture discipline (`tests/adapters/conftest.py::recorded_tool_output`).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest

FIXTURES_ROOT = Path(__file__).parent / "fixtures"


@dataclass(frozen=True)
class ToolConfig:
    """The per-tool surface for the generic parser (D-06-04 / D-06-05).

    `dim` is the caller-supplied `default_dimension` (SARIF carries no dimension
    signal). `map` is the per-tool `{sarif_level: Severity}` override, resolved at
    CALL TIME by `sarif_to_findings`/`map_severity` (Phase 3 precedent:
    `test_overrides_resolved_at_call_time_not_module_load`). It is `{}` for every
    tool here: the faithful default level map (D-06-01) + the security-severity
    numeric band already produce the right severities for all 8 recorded docs, so
    no tool in this corpus needs a level remap. A real adapter would populate
    `map` only to deliberately promote/demote one of its own levels.
    """

    dim: str
    map: dict[str, str] = field(default_factory=dict)


# D-06-05 dimension routing. SARIF gives no dimension signal, so each tool's
# adapter supplies the dimension its findings belong to. severity_map is empty
# for all 8 — the faithful policy + security-severity bands suffice (see above).
TOOL_CONFIG: dict[str, ToolConfig] = {
    "osv-scanner": ToolConfig(dim="security"),
    "semgrep": ToolConfig(dim="security"),
    "mobsfscan": ToolConfig(dim="security"),
    "detekt": ToolConfig(dim="quality"),
    "zizmor": ToolConfig(dim="security"),
    "hadolint": ToolConfig(dim="security"),
    "checkov": ToolConfig(dim="security"),
    "dependency-cruiser": ToolConfig(dim="architecture_rot"),
}

# The 8 tools, in a stable order for parametrization ids.
SARIF_TOOLS: list[str] = list(TOOL_CONFIG)


@pytest.fixture
def load_sarif() -> Callable[[str], dict[str, Any]]:
    """Return a loader for the frozen `fixtures/{tool}/sample.sarif` document.

    Raises FileNotFoundError with a clear message if the fixture is missing so a
    misnamed tool fails loud rather than returning an empty doc.
    """

    def _load(tool: str) -> dict[str, Any]:
        path = FIXTURES_ROOT / tool / "sample.sarif"
        if not path.exists():
            raise FileNotFoundError(
                f"load_sarif({tool!r}) — recorded fixture missing: {path}"
            )
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)

    return _load
