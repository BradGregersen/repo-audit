"""Expo stack-depth adapter package (EXP-01, Phase 11 Wave 1).

Like ``adapters/sca`` / ``adapters/sast`` / ``adapters/mobile`` / ``adapters/kotlin``,
this package does NOT call ``@register_adapter`` here — the expo-doctor collector
is wired by the Phase-11 integration plan (Plan 05) as a dedicated scan step.

It ships:

    * :class:`ExpoResult` — the never-raise envelope (mirrors
      ``kotlin/__init__.py::KotlinResult`` / ``sast/__init__.py::SastResult``
      field-for-field). :func:`doctor.run_expo_doctor` returns this envelope.
    * :func:`doctor.collect_expo_doctor` — the never-raise EXP-01 collector. It
      returns a ``list[Finding]`` directly (the Wave-0 contract test
      ``tests/adapters/expo/test_doctor.py`` indexes the returned list), built by
      a text-scrape of expo-doctor's TEXT-only output (11-RESEARCH Pitfall 3 —
      there is no JSON/SARIF flag): exit-code + per-check failure markers with an
      aggregate-stdout-tail fallback; absent tool → an ``unavailable`` Finding;
      NEVER raises.

``ExpoResult`` mirrors ``KotlinResult`` exactly so the expo collector reads as a
sibling of the other cross-stack collectors.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

from repo_audit.schema.finding import Finding

ExpoStatus = Literal["ok", "unavailable", "timeout"]


@dataclass
class ExpoResult:
    """The never-raise envelope returned by :func:`doctor.run_expo_doctor`.

    Mirrors ``KotlinResult`` / ``SastResult`` field-for-field: every failure
    mode — absent expo-doctor/npx, exec failure, timeout — is folded into
    ``status`` + ``notes`` rather than raised. ``status='ok'`` carries the
    quality findings (one pass Finding, or one-or-more failure Findings).
    """

    findings: list[Finding] = field(default_factory=list)
    status: ExpoStatus = "ok"
    scanner_version: Optional[str] = None
    notes: str = ""


__all__ = ["ExpoResult", "ExpoStatus"]
