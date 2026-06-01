"""Contract tests for the deterministic SARIF severity policy (SC-2, D-06-01).

map_severity(level, security_severity, severity_map) -> Severity

These pin:
- the default faithful level map (error/warning/note/none + missing)
- the security-severity numeric-band refinement that OVERRIDES the level
- the per-tool severity_map override winning over the default table
- that severity_map is consulted at CALL time (caller-supplied dict)
"""
from __future__ import annotations

import pytest

from repo_audit.adapters.sarif import map_severity


class TestDefaultFaithfulLevelMap:
    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            ("error", "critical"),
            ("warning", "major"),
            ("note", "minor"),
            ("none", "info"),
            (None, "info"),  # missing level floors at info (faithful, no invention)
        ],
    )
    def test_default_faithful_level_map(self, level, expected):
        assert map_severity(level, None, {}) == expected


class TestSecuritySeverityBand:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            ("10.0", "critical"),
            ("9.5", "critical"),
            ("9.0", "critical"),
            ("8.9", "major"),
            ("7.0", "major"),
            ("6.9", "minor"),
            ("4.0", "minor"),
            ("3.9", "info"),
            ("0.1", "info"),
        ],
    )
    def test_security_severity_band_maps(self, score, expected):
        # level is warning throughout; the band must drive the result.
        assert map_severity("warning", score, {}) == expected

    def test_security_severity_band_overrides_level(self):
        # band wins over level
        assert map_severity("warning", "9.5", {}) == "critical"
        # a high level loses to a low band score
        assert map_severity("error", "2.0", {}) == "info"

    def test_zero_or_unparseable_security_severity_falls_back_to_level(self):
        assert map_severity("error", "0.0", {}) == "critical"
        assert map_severity("warning", "not-a-number", {}) == "major"
        assert map_severity("note", "", {}) == "minor"


class TestPerToolSeverityMap:
    def test_per_tool_severity_map_wins_over_default(self):
        # default would map warning -> major; the per-tool map promotes it.
        assert map_severity("warning", None, {"warning": "critical"}) == "critical"

    def test_severity_map_resolved_at_call_time(self):
        # Two different calls with two different maps must reflect each map
        # (proves the map is the caller-supplied arg, not a module-load constant).
        first = map_severity("note", None, {"note": "blocker"})
        second = map_severity("note", None, {})
        assert first == "blocker"
        assert second == "minor"

    def test_security_severity_band_overrides_even_a_per_tool_map(self):
        # A present, parseable security-severity is the strongest signal.
        result = map_severity("warning", "9.5", {"warning": "info"})
        assert result == "critical"
