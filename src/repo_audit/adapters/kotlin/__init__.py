"""Kotlin/Android stack-depth adapter package (KOT-01, Phase 11 Wave 1).

Like ``adapters/sca`` / ``adapters/sast`` / ``adapters/mobile``, this package
does NOT call ``@register_adapter`` here — the detekt collector is wired by the
Phase-11 integration plan as a dedicated scan step. This package ships:

    * :class:`KotlinResult` — the never-raise envelope every Kotlin collection
      returns (mirrors ``sast/__init__.py::SastResult`` field-for-field).
    * :func:`noise.apply_detekt_noise_floor` — D-11-08 rule-id-prefix drop
      (``detekt.style.*`` / ``detekt.formatting.*``) + a ``minor`` severity floor,
      overridable via an ``.repo-audit.yaml`` ``kotlin`` block.
    * :func:`typed_build.try_resolve_classpath_via_throwaway_build` — best-effort
      classpath resolution via a Phase-9-shaped ``git archive HEAD`` → tempdir
      gradle build; returns ``None`` on ANY failure so the caller falls back to
      the standalone detekt floor (the KOT-01 guarantee).
    * :func:`detekt.collect_detekt` / :func:`detekt.run_detekt` — the never-raise
      detekt collector mirroring ``sast/semgrep.py``: typed-then-standalone argv,
      ``--build-upon-default-config`` always, a SARIF-FILE gate (not returncode),
      the shared ``sarif_to_findings`` parse path + the noise floor.

``KotlinResult`` mirrors ``SastResult`` exactly so the Kotlin collector reads as
a sibling of the Semgrep/OSV/MobSF collectors: the never-raise envelope a
cross-stack collection returns (findings + status + scanner_version + notes).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

from repo_audit.schema.finding import Finding

KotlinStatus = Literal["ok", "unavailable", "timeout"]


@dataclass
class KotlinResult:
    """The never-raise envelope returned by :func:`detekt.collect_detekt`.

    Mirrors ``SastResult`` field-for-field (the cross-stack collector precedent):
    every failure mode — absent JRE/jar, exec failure, timeout, unparseable
    SARIF — is folded into ``status`` + ``notes`` rather than raised.
    ``status='ok'`` carries the de-noised quality findings; ``scanner_version``
    is the SARIF driver version (FeedProvenance).
    """

    findings: list[Finding] = field(default_factory=list)
    status: KotlinStatus = "ok"
    scanner_version: Optional[str] = None
    notes: str = ""


__all__ = ["KotlinResult", "KotlinStatus"]
