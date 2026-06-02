"""osv native-JSON enrichment — DIRECT/TRANSITIVE + fix version (SCA-03).

SARIF is the SINGLE finding source (FND-01 / CONTEXT.md discretion constraint).
This module reads osv-scanner's NATIVE JSON (``--format json``) ONLY to derive
*attributes* that the SARIF does not carry, and folds them onto the already-built
SARIF findings keyed on ``(cve, package, version)``. It NEVER constructs a
:class:`Finding` (grep-asserted) and NEVER adds or removes a finding — the count
invariant (``len(after) == len(before)``) is the structural proof that JSON is
enrichment, not a second finding parse path.

Confirmed osv JSON field paths (per ``tests/adapters/sca/fixtures/PROVENANCE.md``,
frozen in Plan 02 against vendored osv-scanner 2.3.8 — NOT guesses):

    results[].packages[].package.{name, version, ecosystem}
    results[].packages[].dependency_groups          # null for a flat requirements.txt
    results[].packages[].vulnerabilities[].id        # native id (PYSEC/GHSA)
    results[].packages[].vulnerabilities[].aliases   # holds the CVE + GHSA
    results[].packages[].vulnerabilities[].affected[].ranges[].events[].fixed
                                                     # the ECOSYSTEM 'fixed' event
                                                     # (NOT a FixedVersions field)

A4 honesty (PROVENANCE.md contract 1): ``dependency_groups`` is ``null`` for a
flat ``requirements.txt`` — osv only populates it for group-aware lockfiles
(poetry.lock, Pipfile.lock, package-lock.json, …). When absent we emit
``direct = None`` (UNKNOWN), NEVER a fabricated ``False`` (or ``True``).

``normalize_cve`` / ``normalize_pkg`` are EXPORTED because Plan 04's grype
corroboration MUST key its union on the IDENTICAL normalization so the
``(cve, pkg, version)`` keys line up across the two tools.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from repo_audit.schema.finding import Finding

# Type alias for the enrichment key + payload, documented once.
EnrichmentKey = tuple[str, str, str]  # (normalized_cve, normalized_pkg, version)


def normalize_cve(cve: str) -> str:
    """Canonicalize a vulnerability id (CVE / GHSA / PYSEC) for keying.

    Uppercase + whitespace-stripped. CVEs are already case-stable
    (``CVE-2025-66471``); GHSA/PYSEC ids are uppercased here too so the union
    key in Plan 04's corroboration matches regardless of source casing.

    EXPORTED: Plan 04 corroboration reuses this so osv (CVE) and grype (CVE via
    relatedVulnerabilities) produce the same key.
    """
    return cve.strip().upper()


def normalize_pkg(pkg: str) -> str:
    """Canonicalize a package name for keying.

    Lowercased + whitespace-stripped, and any ecosystem prefix
    (``pypi:urllib3`` / ``pkg:pypi/urllib3``) is stripped to the bare name so an
    osv ``package.name`` and a grype ``artifact.name`` normalize identically.

    EXPORTED: Plan 04 corroboration reuses this for the union key.
    """
    name = pkg.strip().lower()
    # Strip a leading purl-style prefix `pkg:pypi/<name>` -> `<name>`.
    if name.startswith("pkg:"):
        name = name.split("/", 1)[-1]
    # Strip a leading `ecosystem:<name>` prefix -> `<name>`.
    elif ":" in name:
        name = name.split(":", 1)[-1]
    # Drop any trailing `@version` that may ride along on a purl.
    name = name.split("@", 1)[0]
    return name


# osv SARIF message shape (Phase-6 recorded fixture):
#   "Package 'urllib3@1.23.0' is vulnerable to 'CVE-2025-66471' (also known as ...)."
# The package + version live in the FIRST quoted `<name>@<version>` token.
_PKG_AT_VERSION_RE = re.compile(r"'(?P<name>[^'@]+)@(?P<version>[^']+)'")


def enrichment_key_for(finding: Finding) -> EnrichmentKey:
    """Derive the ``(cve, pkg, version)`` enrichment + corroboration key.

    This is the ONE keying function shared by osv enrichment (Plan 03) AND grype
    corroboration (Plan 04) — there is deliberately no fork, so the two tools'
    findings union on byte-identical keys.

    Key sources, in priority order:

    - **Pre-stamped identity (grype, Pitfall 2):** when ``evidence.parsed_value``
      already carries a ``cve`` (and ``package``/``version``), those win. grype's
      SARIF ``ruleId`` is the COMPOSITE ``{vulnID}-{pkg}`` (NOT the bare CVE), so
      ``collect_grype`` re-extracts the canonical CVE/package/version into
      ``parsed_value`` and this branch reads them. This is what lets a grype
      finding key identically to the CVE-keyed osv finding.
    - **osv SARIF shape:** otherwise the CVE is ``finding.rule_id`` (osv's SARIF
      ruleId IS the bare CVE) and the package + version are parsed from
      ``evidence.output_snippet`` (``Package 'urllib3@1.23.0' is vulnerable …``).
    - **parsed_value package/version fallback:** if the message shape does not
      match, ``parsed_value['package']`` / ``['version']`` are used.

    Returns a key with empty package/version strings when nothing matches — an
    unmatched key simply finds no enrichment entry / no corroboration partner,
    leaving the finding intact at ``candidate`` (the apply step defaults
    ``direct=None``).
    """
    pv = finding.evidence.parsed_value or {}

    # Pre-stamped identity wins (grype path, Pitfall 2). The presence of an
    # explicit `cve` in parsed_value signals the rule_id is NOT the bare CVE.
    stamped_cve = pv.get("cve")
    if isinstance(stamped_cve, str) and stamped_cve:
        pkg_raw = pv.get("package")
        version_raw = pv.get("version")
        pkg = normalize_pkg(pkg_raw) if isinstance(pkg_raw, str) else ""
        version = version_raw.strip() if isinstance(version_raw, str) else ""
        return (normalize_cve(stamped_cve), pkg, version)

    cve = normalize_cve(finding.rule_id or "")

    snippet = finding.evidence.output_snippet or ""
    match = _PKG_AT_VERSION_RE.search(snippet)
    if match:
        pkg = normalize_pkg(match.group("name"))
        version = match.group("version").strip()
        return (cve, pkg, version)

    # Fallback: a prior pass may have stamped package/version in parsed_value.
    pkg_raw = pv.get("package")
    version_raw = pv.get("version")
    pkg = normalize_pkg(pkg_raw) if isinstance(pkg_raw, str) else ""
    version = version_raw.strip() if isinstance(version_raw, str) else ""
    return (cve, pkg, version)


def _direct_from_dependency_groups(
    dependency_groups: Any,
) -> Optional[bool]:
    """Map osv ``dependency_groups`` to direct (True/False) or None (unknown).

    A4 honesty (PROVENANCE.md): ``dependency_groups`` is ``null``/absent for a
    flat ``requirements.txt`` — osv only populates it for group-aware lockfiles.
    When absent we return ``None`` (UNKNOWN) and NEVER guess.

    When present, osv lists the groups a package belongs to (e.g. ``["dev"]`` /
    ``["default"]`` / ``["optional"]``). The presence of a non-empty group list
    means osv resolved the package as a direct (declared) dependency of the
    project, so we treat a populated list as ``direct=True``. (Transitive
    packages carry no group membership in osv's group-aware output.)
    """
    if dependency_groups is None:
        return None
    if isinstance(dependency_groups, list):
        return len(dependency_groups) > 0
    # Any other shape is unexpected — be honest, return unknown rather than guess.
    return None


def _fixed_version_for_vuln(vuln: dict[str, Any]) -> Optional[str]:
    """Extract the fix version from a vuln's ECOSYSTEM 'fixed' range event.

    Per PROVENANCE.md contract 2: the fix version is the ``fixed`` event inside
    an ``affected[].ranges[]`` entry (paired with an ``{"introduced": ...}``
    event), NOT a ``FixedVersions`` field. Returns the LAST (highest-introduced)
    ``fixed`` event seen — for a single-range vuln this is the lone fix; when a
    vuln spans multiple introduced/fixed ranges (e.g. a 1.x and a 2.x branch)
    the last range's fix is the most relevant upgrade target for a 1.x pin.
    Returns ``None`` when no ``fixed`` event exists (no fix available).
    """
    fixed: Optional[str] = None
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and "fixed" in event:
                    fixed = event["fixed"]
    return fixed


def build_osv_enrichment(
    osv_json: dict[str, Any],
) -> dict[EnrichmentKey, dict[str, Any]]:
    """Build the ``(cve, pkg, version)`` -> enrichment map from osv native JSON.

    Walks the CONFIRMED paths (PROVENANCE.md) and, for every vulnerability,
    registers an entry under EVERY id/alias of that vuln (so a SARIF finding
    whose ruleId is the CVE matches even when the JSON's native ``id`` is the
    GHSA/PYSEC). Each entry carries:

        direct:        bool | None   # None when dependency_groups absent (A4)
        path_to_root:  list[str]     # best-effort; [] when unavailable
        fixed_version: str | None    # the 'fixed' ECOSYSTEM event; None if no fix

    This function constructs ZERO Findings — it produces a lookup table only.
    """
    enrichment: dict[EnrichmentKey, dict[str, Any]] = {}

    for result in osv_json.get("results") or []:
        if not isinstance(result, dict):
            continue
        for package_entry in result.get("packages") or []:
            if not isinstance(package_entry, dict):
                continue
            package = package_entry.get("package") or {}
            pkg_name = package.get("name")
            pkg_version = package.get("version")
            if not isinstance(pkg_name, str) or not isinstance(pkg_version, str):
                continue
            norm_pkg = normalize_pkg(pkg_name)

            direct = _direct_from_dependency_groups(
                package_entry.get("dependency_groups")
            )
            # path_to_root is not present in osv's flat-lockfile JSON; best-effort
            # empty list (A4 honesty — never fabricated). A group-aware lockfile
            # could populate it later without changing this shape.
            path_to_root: list[str] = []

            for vuln in package_entry.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                fixed_version = _fixed_version_for_vuln(vuln)

                # Index under the native id AND every alias so a CVE-keyed SARIF
                # finding matches even when the JSON id is a GHSA/PYSEC.
                ids: list[str] = []
                vid = vuln.get("id")
                if isinstance(vid, str):
                    ids.append(vid)
                for alias in vuln.get("aliases") or []:
                    if isinstance(alias, str):
                        ids.append(alias)

                payload = {
                    "direct": direct,
                    "path_to_root": path_to_root,
                    "fixed_version": fixed_version,
                }
                for ident in ids:
                    key: EnrichmentKey = (
                        normalize_cve(ident),
                        norm_pkg,
                        pkg_version,
                    )
                    enrichment[key] = payload

    return enrichment


def apply_enrichment(
    findings: list[Finding],
    enrichment: dict[EnrichmentKey, dict[str, Any]],
) -> None:
    """Fold enrichment attributes onto each finding's ``evidence.parsed_value``.

    Mutates in place. For every finding, writes ``direct`` / ``path_to_root`` /
    ``fixed_version`` into ``evidence.parsed_value``. An unmatched finding (no
    enrichment entry for its key) is left intact with ``direct=None`` (UNKNOWN),
    ``path_to_root=[]``, ``fixed_version=None`` — honesty over a fabricated value.

    NEVER adds or removes a finding: ``len(findings)`` is unchanged. This is the
    structural guarantee that osv native JSON is enrichment, not a finding source.
    Also writes a copy of ``recommendation`` (``"upgrade to {fix}"``) when a fix
    is known and the finding has no recommendation yet.
    """
    for finding in findings:
        key = enrichment_key_for(finding)
        entry = enrichment.get(key)
        if entry is None:
            entry = {"direct": None, "path_to_root": [], "fixed_version": None}

        finding.evidence.parsed_value["direct"] = entry["direct"]
        finding.evidence.parsed_value["path_to_root"] = entry["path_to_root"]
        finding.evidence.parsed_value["fixed_version"] = entry["fixed_version"]

        fixed = entry["fixed_version"]
        if fixed and not finding.recommendation:
            finding.recommendation = f"upgrade to {fixed}"


__all__ = [
    "EnrichmentKey",
    "normalize_cve",
    "normalize_pkg",
    "enrichment_key_for",
    "build_osv_enrichment",
    "apply_enrichment",
]
