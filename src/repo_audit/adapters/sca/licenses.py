"""SCA-04 — offline license-risk findings derived from the Syft CycloneDX SBOM.

PITFALL-1 DECISION (RESEARCH option 1 — offline-from-SBOM is the DEFAULT path):
    The network ``osv ... --licenses`` pass collides with the pinned-offline SCA
    posture (Phase 7 runs osv with ``--offline-vulnerabilities`` and a pinned DB;
    licenses via deps.dev would punch a network hole through that). So license
    risk is derived OFFLINE from the Syft CycloneDX SBOM that SUP-02 (plan 12-04)
    already generates — ``components[].licenses[].license.{id,name}`` — with NO
    network egress on the default path (T-12-03-NET mitigation). The network
    ``--licenses`` fallback is left as a documented, OFF-by-default seam
    (``_osv_licenses_argv``); it is NOT wired into the offline scan path.

DIMENSION ROUTING (Claude's Discretion, D-12): risky-license findings are routed
to the ``security`` dimension. Rationale: a copyleft (GPL/AGPL) obligation on a
shipped dependency is a legal/compliance EXPOSURE risk — it is framed as a
supply-chain exposure alongside the CVE/MAL findings in the security dimension,
not as code quality. (``quality`` was the alternative; ``security`` chosen for
the copyleft-exposure framing so license risk sits with the other SBOM-derived
supply-chain signal.)

SEVERITY (D-12-08): license risk is REAL but LOW prominence — every license
finding is ``severity='minor'``, ``confidence='candidate'``, ``evidence_type=
'static'`` with NO confidence_caveat (SCH-04 permits minor+candidate; SAFE-01
only fires on critical+static). "Real over volume."
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional

from repo_audit.schema.finding import Evidence, Finding

LicensesStatus = Literal["ok", "unavailable"]

# Copyleft / risky SPDX license families flagged as a minor exposure finding.
# Matched case-insensitively as a substring of the SPDX id/name so 'GPL-3.0-only',
# 'AGPL-3.0-or-later', 'LGPL-2.1' all match their family prefix.
_RISKY_LICENSE_FAMILIES: tuple[str, ...] = ("AGPL", "LGPL", "GPL")

# The dimension risky-license findings route to (documented discretion above).
_LICENSE_DIMENSION: str = "security"


@dataclass
class LicensesResult:
    """The never-raise envelope returned by :func:`collect_licenses`.

    Mirrors the OsvResult contract: every failure mode is a status + notes, never
    an exception. ``findings`` is empty + ``status='unavailable'`` when the SBOM
    is missing/unreadable or carries no components.
    """

    findings: list[Finding] = field(default_factory=list)
    status: LicensesStatus = "ok"
    notes: str = ""


def _load_sbom(sbom: Any) -> Optional[dict]:
    """Resolve ``sbom`` (a parsed CycloneDX dict OR a Path/str to one) to a dict.

    Accepts both the Wave-0 test shape (the already-parsed SBOM dict) and the
    runtime-wiring shape (a path to ``syft-cyclonedx.json``). Returns ``None``
    when the SBOM is absent or unreadable — the caller maps that to
    ``status='unavailable'`` (never raises).
    """
    if sbom is None:
        return None
    if isinstance(sbom, dict):
        return sbom
    if isinstance(sbom, (str, Path)):
        path = Path(sbom)
        try:
            import json

            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
    return None


def _license_ids(component: dict) -> list[str]:
    """Extract SPDX license ids/names from a CycloneDX ``component``.

    CycloneDX carries licenses as ``licenses: [{license: {id|name}}]`` (and
    occasionally ``{expression: "..."}``). Returns the non-empty string ids/names;
    an empty list means the component declares NO license (the unknown path).
    """
    out: list[str] = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        lic = entry.get("license")
        if isinstance(lic, dict):
            val = lic.get("id") or lic.get("name")
            if isinstance(val, str) and val.strip():
                out.append(val.strip())
        expr = entry.get("expression")
        if isinstance(expr, str) and expr.strip():
            out.append(expr.strip())
    return out


def _risky_family(license_id: str) -> Optional[str]:
    """Return the matched copyleft family for ``license_id``, else ``None``."""
    upper = license_id.upper()
    for fam in _RISKY_LICENSE_FAMILIES:
        if fam in upper:
            return fam
    return None


def _license_finding(
    *,
    package: str,
    snippet: str,
    parsed_value: dict[str, Any],
) -> Finding:
    """Build one minor/candidate license-risk Finding (no caveat — SCH-04 ok)."""
    return Finding(
        dimension=_LICENSE_DIMENSION,  # type: ignore[arg-type]  # validated
        severity="minor",
        file=package,  # the offending package name (Wave-0 test reads f.file)
        line=None,
        evidence=Evidence(
            tool="syft-sbom",
            output_snippet=snippet,
            parsed_value=parsed_value,
        ),
        evidence_type="static",
        confidence="candidate",
        source_tool="syft-sbom",
        source_collector="license_risk",
        rule_id="LICENSE-RISK",
    )


def collect_licenses(sbom: Any) -> LicensesResult:
    """Derive license-risk findings OFFLINE from a CycloneDX SBOM.

    Args:
        sbom: a parsed CycloneDX SBOM ``dict`` (the Wave-0 test shape) OR a
            ``Path``/``str`` to the ``syft-cyclonedx.json`` file (the runtime
            shape), OR ``None`` when no SBOM was generated.

    Returns:
        A :class:`LicensesResult`. For each component with a copyleft (GPL/AGPL/
        LGPL) license -> a ``minor``/``candidate`` Finding; for each component
        with NO declared license -> an ``unknown-license`` Finding (also
        ``minor``/``candidate``). When ``sbom`` is ``None``/unreadable or has no
        components -> ``status='unavailable'`` + empty findings. Never raises.
    """
    data = _load_sbom(sbom)
    if data is None:
        return LicensesResult(
            status="unavailable",
            findings=[],
            notes="no SBOM available — license risk not derived (offline path)",
        )

    components = data.get("components")
    if not isinstance(components, list) or not components:
        return LicensesResult(
            status="unavailable",
            findings=[],
            notes="SBOM has no components — nothing to classify",
        )

    findings: list[Finding] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        package = component.get("name")
        if not isinstance(package, str) or not package.strip():
            continue
        package = package.strip()
        version = component.get("version")

        license_ids = _license_ids(component)
        if not license_ids:
            # Unknown / no-license component — surfaced as a minor candidate.
            findings.append(
                _license_finding(
                    package=package,
                    snippet=f"{package} declares no license (unknown-license risk)",
                    parsed_value={
                        "package": package,
                        "version": version,
                        "license": None,
                        "risk": "unknown-license",
                    },
                )
            )
            continue

        risky = [
            (lic, fam) for lic in license_ids if (fam := _risky_family(lic))
        ]
        for lic, fam in risky:
            findings.append(
                _license_finding(
                    package=package,
                    snippet=f"{package} is licensed {lic} (copyleft {fam} exposure)",
                    parsed_value={
                        "package": package,
                        "version": version,
                        "license": lic,
                        "risk": f"copyleft-{fam.lower()}",
                    },
                )
            )

    return LicensesResult(findings=findings, status="ok", notes="")


def _osv_licenses_argv(binary: Path, repo_path: Path) -> list[str]:
    """DOCUMENTED, OFF-BY-DEFAULT network fallback argv (deps.dev egress).

    NOT wired into the offline scan path. ``osv ... --licenses`` reaches deps.dev
    over the network, which collides with the pinned-offline SCA posture
    (T-12-03-NET). This seam exists only so a future, explicitly-opted-in
    network license pass has a single argv builder to clone; the default
    offline-from-SBOM path above never calls it.
    """
    return [
        str(binary),
        "scan",
        "source",
        "--recursive",
        "--experimental-licenses-summary",
        "--format",
        "json",
        str(repo_path),
    ]


__all__ = ["LicensesResult", "LicensesStatus", "collect_licenses"]
