"""Supabase RLS / data-privacy adapter package (Phase 08).

Plan 05 closes the phase: this module composes every Wave 1 collector
(splinter floor + flag-gated pgrls + always-on squawk/footguns + flag-gated
runtime) into a single RLS dimension via :func:`run_supabase`, records the
D-08-09/16 reproducibility provenance + the D-08-05 not-run posture as ledger
notes, and registers the ``supabase`` adapter (the side-effect import in
``cli.py`` triggers ``@register_adapter('supabase')``).

Like the cross-stack SCA package (Phase 7), the HEAVY work runs as a dedicated
``scan_runner`` step (``run_supabase``) rather than per-stack dispatch — the
ephemeral-DB lifecycle + the ``--rls-pgrls`` / ``--rls-runtime`` flag gating sit
ABOVE per-stack dispatch. The registered ``run()`` is a thin marker so the
detector + scope ledger see the adapter (D-40); the cross-stack step is the real
entry point ``scan_runner.run_scan`` invokes.

Composition contract (the KEY CONTRACTS):
    * splinter is ALWAYS-ON (the floor); pgrls runs ONLY when ``rls_pgrls`` AND
      against the SAME ephemeral DB the floor stands up (one lifecycle); squawk +
      footguns are always-on static; the runtime two-account probe runs ONLY when
      ``rls_runtime`` (and its own six-name gate, enforced inside the collector).
    * ``run_supabase`` NEVER raises (base.py contract) — any failure degrades the
      RLS dimension to ``unavailable`` with a clear reason rather than aborting
      the scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version
from pathlib import Path
from typing import Any, Literal

from ruamel.yaml import YAML

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.registry import register_adapter
from repo_audit.adapters.supabase.discovery import (
    detect_pg_major,
    find_migrations,
)
from repo_audit.adapters.supabase.footguns import scan_service_role_in_client
from repo_audit.adapters.supabase.pgproof import (
    SUPABASE_PG_IMAGES,
    EphemeralPgUnavailable,
    MigrationApplyFailed,
    ephemeral_supabase_pg,
)
from repo_audit.adapters.supabase.pgrls_collect import (
    collect_pgrls,
    pgrls_version,
)
from repo_audit.adapters.supabase.provenance import (
    build_rls_provenance,
    provenance_note,
    read_splinter_sha,
)
from repo_audit.adapters.supabase.runtime_two_account import (
    collect_runtime_two_account,
)
from repo_audit.adapters.supabase.splinter_collect import (
    map_splinter_rows,
    run_splinter,
)
from repo_audit.adapters.supabase.squawk_collect import collect_squawk
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)
from repo_audit.schema.finding import Finding

# --- adapter.yaml load (T-03-01 safe-mode) --------------------------------

_ADAPTER_YAML_PATH = Path(__file__).parent / "adapter.yaml"


def _load_adapter_yaml() -> dict[str, Any]:
    """Load ``adapter.yaml`` under ruamel.yaml's safe loader (T-03-01)."""
    yaml = YAML(typ="safe")
    with _ADAPTER_YAML_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.load(fh)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"adapter.yaml at {_ADAPTER_YAML_PATH} did not load as a mapping; "
            f"got {type(data).__name__}"
        )
    return data


ADAPTER_CONFIG: dict[str, Any] = _load_adapter_yaml()
CONFIG: dict[str, Any] = ADAPTER_CONFIG

# Per-tool timeouts (ms in yaml -> seconds here). Fall back to sane defaults.
_TOOLS = ADAPTER_CONFIG.get("tools", {})


def _timeout_s(tool: str, default: float) -> float:
    cfg = _TOOLS.get(tool, {})
    ms = cfg.get("timeout_ms")
    return float(ms) / 1000.0 if isinstance(ms, (int, float)) else default


_SPLINTER_TIMEOUT = _timeout_s("splinter", 120.0)
_PGRLS_TIMEOUT = _timeout_s("pgrls", 120.0)
_SQUAWK_TIMEOUT = _timeout_s("squawk", 60.0)
_RUNTIME_TIMEOUT = _timeout_s("rls-two-account", 300.0)
_APPLY_TIMEOUT = _timeout_s("psql", 120.0)


def _squawk_version() -> str:
    """Best-effort squawk version for provenance (dist metadata, else unknown)."""
    for dist in ("squawk", "squawk-cli"):
        try:
            return _dist_version(dist)
        except PackageNotFoundError:
            continue
    return "unknown"


def _image_ref_for(pg_major: int) -> str:
    """The pinned supabase/postgres image tag@digest for ``pg_major`` (or 15)."""
    return SUPABASE_PG_IMAGES.get(pg_major) or SUPABASE_PG_IMAGES.get(15, "unknown")


# --- run_supabase: the cross-stack RLS orchestration entry point ----------

SupabaseStatus = Literal["ok", "partial", "unavailable"]


@dataclass
class SupabaseScanResult:
    """The never-raise envelope returned by :func:`run_supabase`.

    ``scan_runner`` reads ``findings`` into the merged finding set, folds
    ``ledger_notes`` (the not-run posture + the provenance stamp) into the scope
    ledger, and may stash ``provenance`` for a report header. ``status`` /
    ``notes`` describe the RLS dimension's overall availability.
    """

    findings: list[Finding] = field(default_factory=list)
    status: SupabaseStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)
    provenance: dict[str, str] = field(default_factory=dict)


def _runtime_posture(opted_in: bool, runtime_result: AdapterResult | None) -> str:
    """Derive the D-08-05 honest runtime posture from the runtime outcome."""
    if not opted_in:
        return "not_run_not_opted_in"
    if runtime_result is None:
        return "not_run_not_opted_in"
    if runtime_result.status == "ok":
        # Exactly one runtime finding; blocker -> leak, else pass.
        for f in runtime_result.findings:
            if f.severity == "blocker":
                return "run_leak"
        return "run_pass"
    # Opted in but did not produce a verdict: missing creds vs a real error.
    note = (runtime_result.notes or "").lower()
    if "no creds" in note or "missing" in note or "not opted in" in note:
        return "not_run_no_creds"
    return "run_error"


def run_supabase(
    repo: Path,
    *,
    base_env: dict[str, str],
    rls_pgrls: bool = False,
    rls_runtime: bool = False,
) -> SupabaseScanResult:
    """Compose the whole RLS dimension behind ONE ephemeral-DB lifecycle.

    Pipeline:
        1. ``find_migrations`` + ``detect_pg_major``.
        2. open ``ephemeral_supabase_pg`` ONCE (when migrations exist): run
           splinter (floor) AND, when ``rls_pgrls``, ``collect_pgrls`` against the
           SAME dsn — then tear down.
        3. ALWAYS run ``collect_squawk`` (static, no DB) + ``scan_service_role_in_client``.
        4. run ``collect_runtime_two_account(opted_in=rls_runtime, ...)`` (the
           collector's own six-name gate still applies; it never auto-runs).
        5. merge findings, assert verify-phrasing over the STATIC findings (the
           runtime findings are the sanctioned exemption), record the not-run
           posture (D-08-05) + the reproducibility provenance (D-08-09/16) as
           ledger notes.

    NEVER raises — any unexpected error degrades to ``status="unavailable"``.

    Args:
        repo: the target repository root.
        base_env: the child env (a ``build_scan_env`` tempdir env) passed to
            every tool invocation (caches redirected OUTSIDE the repo, SC-5).
        rls_pgrls: run the additive pgrls layer (default off — splinter is floor).
        rls_runtime: opt into the runtime two-account probe (default off).

    Returns:
        A :class:`SupabaseScanResult`; never raises.
    """
    repo = Path(repo)
    base_env = dict(base_env or {})
    findings: list[Finding] = []
    ledger_notes: list[str] = []
    notes_parts: list[str] = []
    statuses: list[str] = []

    try:
        mig = find_migrations(repo)
    except Exception as exc:  # noqa: BLE001 — absolute never-raise backstop
        return SupabaseScanResult(
            status="unavailable",
            findings=[],
            notes=f"RLS discovery failed: {type(exc).__name__}: {exc}",
            ledger_notes=[f"RLS dimension unavailable: discovery failed ({exc})"],
        )

    pg_major = detect_pg_major(repo)
    layout = mig.layout

    # --- 2. The floor (splinter) + flag-gated pgrls behind ONE lifecycle. ---
    if mig.layout == "none":
        ledger_notes.append(
            "RLS-01 splinter floor unavailable: no migrations found "
            "(searched supabase/migrations and **/sql/00N_*.sql)"
        )
        statuses.append("unavailable")
        notes_parts.append("splinter: no migrations")
    else:
        try:
            from repo_audit.adapters.cache_env import scan_tempdir

            with scan_tempdir() as tempdir:
                with ephemeral_supabase_pg(
                    mig.files,
                    pg_major=pg_major,
                    env=base_env,
                    cwd=tempdir,
                    timeout_seconds=_SPLINTER_TIMEOUT,
                ) as dsn:
                    # Splinter floor — always.
                    rows = run_splinter(dsn, timeout_seconds=_SPLINTER_TIMEOUT)
                    splinter_findings = map_splinter_rows(rows)
                    findings.extend(splinter_findings)
                    notes_parts.append(f"splinter: {len(splinter_findings)} finding(s)")
                    statuses.append("ok")
                    # pgrls additive layer — ONLY when flagged, SAME dsn.
                    if rls_pgrls:
                        pgrls_result = collect_pgrls(
                            dsn,
                            env=base_env,
                            timeout_seconds=_PGRLS_TIMEOUT,
                            scan_target=repo,
                        )
                        findings.extend(pgrls_result.findings)
                        statuses.append(pgrls_result.status)
                        if pgrls_result.status != "ok":
                            ledger_notes.append(
                                f"pgrls additive layer {pgrls_result.status}: "
                                f"{pgrls_result.notes}"
                            )
                        else:
                            notes_parts.append(
                                f"pgrls: {len(pgrls_result.findings)} finding(s)"
                            )
        except (EphemeralPgUnavailable, MigrationApplyFailed) as exc:
            ledger_notes.append(
                "RLS-01 splinter floor unavailable (no stock-postgres fallback, "
                f"D-08-10): {type(exc).__name__}: {exc}"
            )
            statuses.append("unavailable")
            notes_parts.append("splinter: ephemeral DB unavailable")
        except Exception as exc:  # noqa: BLE001 — never crash the dimension
            ledger_notes.append(
                f"RLS-01 splinter floor failed unexpectedly: {type(exc).__name__}: {exc}"
            )
            statuses.append("unavailable")
            notes_parts.append("splinter: unexpected error")

    # --- 3. Always-on static layers (no DB). --------------------------------
    try:
        squawk_result = collect_squawk(
            mig.files,
            env=base_env,
            timeout_seconds=_SQUAWK_TIMEOUT,
            scan_target=repo,
        )
        findings.extend(squawk_result.findings)
        statuses.append(squawk_result.status)
        if squawk_result.status != "ok":
            ledger_notes.append(
                f"squawk migration-safety {squawk_result.status}: {squawk_result.notes}"
            )
        else:
            notes_parts.append(f"squawk: {len(squawk_result.findings)} finding(s)")
    except Exception as exc:  # noqa: BLE001 — never crash the dimension
        ledger_notes.append(f"squawk failed unexpectedly: {type(exc).__name__}: {exc}")
        statuses.append("unavailable")

    try:
        footgun_result = scan_service_role_in_client(repo)
        findings.extend(footgun_result.findings)
        statuses.append(footgun_result.status)
        if footgun_result.status != "ok":
            ledger_notes.append(
                f"service_role-in-client grep {footgun_result.status}: "
                f"{footgun_result.notes}"
            )
        else:
            notes_parts.append(f"footguns: {len(footgun_result.findings)} finding(s)")
    except Exception as exc:  # noqa: BLE001 — never crash the dimension
        ledger_notes.append(f"footguns failed unexpectedly: {type(exc).__name__}: {exc}")
        statuses.append("unavailable")

    # --- 4. Runtime two-account probe (flag-gated + its own six-name gate). --
    runtime_result: AdapterResult | None = None
    try:
        runtime_result = collect_runtime_two_account(
            repo,
            opted_in=rls_runtime,
            env=base_env,
            timeout_seconds=_RUNTIME_TIMEOUT,
        )
        findings.extend(runtime_result.findings)
        # A runtime finding never flips the dimension to unavailable; the not-run
        # posture below carries the honest disclosure.
    except Exception as exc:  # noqa: BLE001 — never crash the dimension
        ledger_notes.append(f"runtime probe failed unexpectedly: {type(exc).__name__}: {exc}")

    posture = _runtime_posture(rls_runtime, runtime_result)
    if posture.startswith("not_run"):
        ledger_notes.append(
            "Runtime RLS enforcement test not run "
            f"({'not opted in' if posture == 'not_run_not_opted_in' else 'no creds'}) "
            "— no enforcement claim is made (D-08-05)."
        )
    elif posture == "run_pass":
        ledger_notes.append(
            "Runtime two-account test ran: PASS (RLS enforced cross-tenant on probed tables)."
        )
    elif posture == "run_leak":
        ledger_notes.append(
            "Runtime two-account test ran: LEAK (cross-tenant data leak observed)."
        )
    else:
        ledger_notes.append(
            f"Runtime two-account test ran with an error: {runtime_result.notes if runtime_result else ''}"
        )

    # --- 5. CRIT-4 over the STATIC findings (runtime exempt). ---------------
    static_findings = [f for f in findings if f.evidence_type != "runtime"]
    try:
        assert_verify_phrasing(static_findings)
    except Exception as exc:  # noqa: BLE001 — a tripwire fault must not abort
        ledger_notes.append(
            f"verify-phrasing tripwire flagged a static finding: {exc}"
        )

    # --- Provenance (D-08-09/16). -------------------------------------------
    provenance = build_rls_provenance(
        splinter_sha=read_splinter_sha(),
        pgrls_version=pgrls_version() if rls_pgrls else pgrls_version(),
        squawk_version=_squawk_version(),
        image_ref=_image_ref_for(pg_major),
        layout=layout,
        runtime_posture=posture,
    )
    ledger_notes.append(provenance_note(provenance))

    # --- Overall status. ----------------------------------------------------
    if all(s == "ok" for s in statuses) and statuses:
        status: SupabaseStatus = "ok"
    elif any(s == "ok" for s in statuses):
        status = "partial"
    else:
        status = "unavailable"

    return SupabaseScanResult(
        findings=findings,
        status=status,
        notes="; ".join(notes_parts),
        ledger_notes=ledger_notes,
        provenance=provenance,
    )


@register_adapter("supabase")
def run(repo_path, detection):  # noqa: ANN001, ANN201 — registry signature
    """Per-stack registration marker (D-40).

    The HEAVY RLS composition runs as the dedicated cross-stack
    ``scan_runner.run_supabase`` step (mirroring the Phase 7 SCA step), because
    the ephemeral-DB lifecycle + the ``--rls-pgrls`` / ``--rls-runtime`` flag
    gating sit ABOVE per-stack dispatch (the per-stack ``run`` has no access to
    the CLI flags). This registered entry exists so the detector + scope ledger
    SEE the ``supabase`` adapter; it returns no findings of its own — they all
    flow through the cross-stack step.
    """
    return []


__all__ = [
    "ADAPTER_CONFIG",
    "CONFIG",
    "SupabaseScanResult",
    "SupabaseStatus",
    "build_rls_provenance",
    "collect_pgrls",
    "collect_runtime_two_account",
    "collect_squawk",
    "detect_pg_major",
    "ephemeral_supabase_pg",
    "find_migrations",
    "map_splinter_rows",
    "pgrls_version",
    "provenance_note",
    "read_splinter_sha",
    "run",
    "run_supabase",
    "run_splinter",
    "scan_service_role_in_client",
]
