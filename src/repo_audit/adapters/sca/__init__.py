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

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional

from ruamel.yaml import YAML

from repo_audit.adapters.sca.corroborate import corroborate
from repo_audit.adapters.sca.db_env import build_sca_env, sca_db_dir
from repo_audit.adapters.sca.grype import GrypeResult, collect_grype
from repo_audit.adapters.sca.osv import OsvResult, collect_osv
from repo_audit.adapters.sca.partition import ScaPartition, partition
from repo_audit.adapters.sca.provenance import build_feed_provenance
from repo_audit.adapters.sca.refresh import refresh_vuln_db
from repo_audit.schema.finding import Finding
from repo_audit.schema.report import FeedProvenance

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


# --- run_sca: the cross-stack SCA orchestration entry point (Plan 05) ------

ScaStatus = Literal["ok", "unavailable"]


@dataclass
class ScaScanResult:
    """The never-raise envelope returned by :func:`run_sca`.

    Carries the merged + corroborated SCA findings, the headline/appendix
    partition (None when the dimension is unavailable), the per-source
    FeedProvenance list, an overall status, and folded notes. scan_runner reads
    ``findings`` into the merged finding set and ``feed_provenance`` onto
    ReportMeta; ``status``/``notes`` fold into the scope ledger.
    """

    findings: list[Finding] = field(default_factory=list)
    partition: Optional[ScaPartition] = None
    feed_provenance: list[FeedProvenance] = field(default_factory=list)
    status: ScaStatus = "ok"
    notes: str = ""


def _db_seeded() -> bool:
    """True when both osv + grype DB subdirs already hold a snapshot file.

    Used to decide the FIRST-RUN SEED (D-07-01): an EMPTY DB dir means no
    snapshot yet, so we seed once. An existing snapshot is NEVER advanced except
    by an explicit ``refresh`` (CRIT-3).
    """
    db_dir = sca_db_dir()
    osv_dir = db_dir / "osv"
    grype_dir = db_dir / "grype"
    # Require an actual DB FILE, not merely an empty subdir — osv/grype create
    # their nested ecosystem/schema directories before the download lands, so a
    # path-existence check would false-positive on a half-created tree.
    osv_has = osv_dir.is_dir() and any(p.is_file() for p in osv_dir.rglob("*"))
    grype_has = grype_dir.is_dir() and any(p.is_file() for p in grype_dir.rglob("*"))
    return osv_has and grype_has


def run_sca(
    repo_path: Path,
    *,
    base_env: dict[str, str],
    refresh: bool = False,
) -> ScaScanResult:
    """Run the cross-stack SCA step: osv (floor) + grype (optional) → findings.

    Composes the whole SCA pipeline behind the PERSISTENT DB env:
    ``build_sca_env`` → (optional refresh / first-run seed) → ``collect_osv`` →
    ``collect_grype`` → ``corroborate`` → ``partition`` → ``build_feed_provenance``.

    Args:
        repo_path: the repo to scan (osv recurses; grype scans ``dir:``).
        base_env: the base child env (typically a ``build_scan_env`` tempdir env);
            ``build_sca_env`` layers the persistent DB-cache dirs on top.
        refresh: when True, advance BOTH snapshots first via ``refresh_vuln_db``
            (the explicit, sole advance path). When False, the DB is pinned —
            EXCEPT the one-time first-run seed when no snapshot exists (D-07-01).

    Returns:
        A :class:`ScaScanResult`; never raises. osv unavailable → the WHOLE SCA
        dimension is unavailable (status='unavailable', no findings, D-07-10);
        grype unavailable → osv-only (one FeedProvenance entry).
    """
    env = build_sca_env(base_env)
    notes_parts: list[str] = []

    # Explicit advance (the sole snapshot-update path) OR one-time first-run seed.
    if refresh:
        refresh_result = refresh_vuln_db(env)
        notes_parts.append(refresh_result.notes or "vuln-db refreshed")
    elif not _db_seeded():
        # First-run SEED (D-07-01): seed ONCE when no snapshot exists, then pin.
        # Seeding != updating — an existing snapshot is never advanced here.
        # osv downloads against the packaged seed_manifests/ (one manifest per
        # detected ecosystem), so every ecosystem's DB lands under <db>/osv.
        seed_result = refresh_vuln_db(env)
        notes_parts.append(f"first-run vuln-db seed: {seed_result.notes}")

    # osv is the FLOOR (D-07-10): unavailable osv → whole dimension unavailable.
    osv = collect_osv(repo_path, env)
    if osv.status != "ok":
        return ScaScanResult(
            status="unavailable",
            findings=[],
            partition=None,
            feed_provenance=[],
            notes="; ".join(
                notes_parts
                + [f"osv-scanner {osv.status} — SCA dimension unavailable: {osv.notes}"]
            ),
        )

    # grype is OPTIONAL: unavailable → osv-only, no corroboration bump.
    grype = collect_grype(repo_path, env)
    if grype.status != "ok":
        notes_parts.append(f"grype {grype.status} (osv-only): {grype.notes}")

    grype_findings = grype.findings if grype.status == "ok" else []
    findings = corroborate(osv.findings, grype_findings)
    part = partition(findings)
    prov = build_feed_provenance(osv, grype, queried_at=datetime.now())

    return ScaScanResult(
        findings=findings,
        partition=part,
        feed_provenance=prov,
        status="ok",
        notes="; ".join(notes_parts),
    )


__all__ = [
    "ADAPTER_CONFIG",
    "CONFIG",
    "ScaScanResult",
    "ScaStatus",
    "run_sca",
    "collect_osv",
    "collect_grype",
    "corroborate",
    "partition",
    "build_feed_provenance",
    "refresh_vuln_db",
]
