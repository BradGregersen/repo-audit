"""Trend memory: pure-Python delta engine + three-way finding classification.

TREND-01/02/03. Deltas are computed deterministically from the prior + current
``ScanReport`` (TREND-02 / D-05-07: the agent never computes or invents numbers).
"""
from __future__ import annotations

from repo_audit.trend.delta import compute_trend, composite_finding_ref

__all__ = ["compute_trend", "composite_finding_ref"]
