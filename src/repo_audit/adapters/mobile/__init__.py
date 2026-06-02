"""Mobile adapter package — native + JS mobile security collectors (Phase 9).

Plan 05 closes the phase: this module composes the four independent tier modules
(Tier-1 ``mobsfscan`` static SAST + Tier-2 Expo/RN ``bundled-secrets`` + Tier-3a
MobSF Docker static scan + Tier-3b Gradle diagnostic build) into ONE
never-raising mobile-security dimension via :func:`run_mobile`, and registers
the ``mobile`` adapter (the side-effect import in ``cli.py`` triggers
``@register_adapter('mobile')``).

Like the cross-stack SCA package (Phase 7) and the RLS package (Phase 8), the
HEAVY work runs as a dedicated ``scan_runner`` step (``run_mobile``) rather than
per-stack dispatch — the ``--mobsf`` / ``--mobsf-build`` / ``--apk`` flag gating
sits ABOVE per-stack dispatch (the per-stack ``run`` has no access to the CLI
flags). The registered ``run()`` is a thin marker so the detector + scope ledger
SEE the adapter (D-40); the cross-stack step is the real entry point.

Tier gating contract (the KEY CONTRACTS):
    * Tier 1 (mobsfscan) runs by DEFAULT when a native ``android/`` source
      exists — no build, no Docker.
    * Tier 2 (bundled-secrets) ALWAYS runs — no build, no Docker.
    * Tier 3a (MobSF) runs ONLY when ``mobsf`` is truthy AND an existing APK is
      found (or supplied via ``apk``); ``--mobsf-build`` is the ONLY path that
      produces one (Tier 3b assembleDebug, in a throwaway copy).
    * ``run_mobile`` NEVER raises — any unavailable tier degrades the mobile
      dimension and is disclosed in the scope ledger (SAFE-08); the scan still
      completes. Every MobSF-surfaced secret is already redacted at the adapter
      boundary (Plan 03) BEFORE it reaches a Finding here (T-09-04).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ruamel.yaml import YAML

from repo_audit.adapters.cache_env import scan_tempdir
from repo_audit.adapters.mobile.bundled_secrets import scan_bundled_secrets
from repo_audit.adapters.mobile.diagnostic_build import (
    BuildResult,
    build_debug_apk_copy,
)
from repo_audit.adapters.mobile.mobsf import collect_mobsf, find_debug_apk
from repo_audit.adapters.mobile.mobsfscan import (
    collect_mobsfscan,
    run_mobsfscan,
)
from repo_audit.adapters.registry import register_adapter
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


_MOBSFSCAN_TIMEOUT = _timeout_s("mobsfscan", 180.0)
_MOBSF_TIMEOUT = _timeout_s("mobsf", 600.0)
_BUILD_TIMEOUT = _timeout_s("gradle-assemble-debug", 900.0)

# The pinned MobSF image (tag@digest) the Tier-3a collector receives (T-09-10 —
# Plan 05 owns the pin; collect_mobsf never hard-codes it). Falls back to a loud
# unpinned marker if the yaml key is somehow absent (never silently empty).
_MOBSF_IMAGE: str = str(
    ADAPTER_CONFIG.get("mobsf_image")
    or "opensecurity/mobile-security-framework-mobsf:latest"  # pragma: no cover
)


def _native_root(repo: Path) -> Path:
    """Resolve the native Android source root (the dir containing ``android/``).

    The mobsfscan collector scans the native source tree; for a conventional
    Expo/RN repo that is ``<repo>/android``. Returns the ``android/`` dir when it
    exists, else ``repo`` itself (the collector re-checks existence and degrades
    to ``unavailable`` when there is no native source).
    """
    android = Path(repo) / "android"
    return android if android.exists() else Path(repo)


# --- run_mobile: the cross-stack mobile orchestration entry point ----------

MobileStatus = Literal["ok", "partial", "unavailable"]


@dataclass
class MobileScanResult:
    """The never-raise envelope returned by :func:`run_mobile`.

    ``scan_runner`` reads ``findings`` into the merged finding set and folds
    ``ledger_notes`` (the per-tier not-run / unavailable disclosures) into the
    scope ledger. ``status`` / ``notes`` describe the mobile dimension's overall
    availability.
    """

    findings: list[Finding] = field(default_factory=list)
    status: MobileStatus = "ok"
    notes: str = ""
    ledger_notes: list[str] = field(default_factory=list)


def run_mobile(
    repo: Path,
    *,
    base_env: dict[str, str],
    mobsf: bool = False,
    mobsf_build: bool = False,
    apk: Path | None = None,
) -> MobileScanResult:
    """Compose Tiers 1-3 into ONE never-raising mobile-security dimension.

    Pipeline:
        1. Tier 1 (mobsfscan): resolve ``native_root``. If a native ``android/``
           source exists, run ``collect_mobsfscan`` (no build, no Docker). Else a
           ledger note discloses the skip.
        2. Tier 2 (bundled-secrets): ALWAYS run ``scan_bundled_secrets`` (no
           build, no Docker — the default Expo/RN shipped-service_role pass).
        3. Tier 3a/3b gating (off by default):
             * ``mobsf`` truthy → ``find_debug_apk(repo, apk)``. If no APK is
               found AND ``mobsf_build`` is truthy → Tier 3b: open a tempdir that
               OUTLIVES the build, ``build_debug_apk_copy`` (assembleDebug, in a
               throwaway copy), and on ``BuildResult.status == "ok"`` use the
               built APK. Then Tier 3a: ``collect_mobsf`` against the APK, INSIDE
               the tempdir context so a built APK still exists.
             * ``mobsf`` truthy, ``mobsf_build`` False, no APK → ledger note
               ("pass --mobsf-build to produce one"); NEVER builds.
             * ``mobsf`` falsy → Tiers 3a/3b never run.
        4. Merge findings; derive overall status (all ok→ok, some ok→partial,
           none→unavailable); fold each tier's notes / unavailable reasons into
           ``ledger_notes`` (SAFE-08 honest disclosure).

    NEVER raises — any unexpected error degrades to ``status="unavailable"``.

    Args:
        repo: the target repository root.
        base_env: the child env (a ``build_scan_env`` tempdir env) passed to
            every tier (caches redirected OUTSIDE the repo, SC-5).
        mobsf: open Tier 3a (existing-APK MobSF Docker scan); default off.
        mobsf_build: the ONLY path to Tier 3b (assembleDebug); default off.
        apk: an explicit debug-APK path for Tier 3a (supplied via ``--apk``).

    Returns:
        A :class:`MobileScanResult`; never raises.
    """
    repo = Path(repo)
    base_env = dict(base_env or {})
    findings: list[Finding] = []
    ledger_notes: list[str] = []
    notes_parts: list[str] = []
    statuses: list[str] = []

    try:
        # --- Tier 1: mobsfscan over the native android/ source (default). ----
        native_root = _native_root(repo)
        if (repo / "android").exists():
            try:
                t1 = collect_mobsfscan(
                    native_root,
                    env=base_env,
                    timeout_seconds=_MOBSFSCAN_TIMEOUT,
                )
                findings.extend(t1.findings)
                statuses.append(t1.status)
                if t1.status != "ok":
                    ledger_notes.append(
                        f"Tier-1 mobsfscan {t1.status}: {t1.notes}"
                    )
                else:
                    notes_parts.append(f"mobsfscan: {len(t1.findings)} finding(s)")
            except Exception as exc:  # noqa: BLE001 — never crash the dimension
                ledger_notes.append(
                    f"Tier-1 mobsfscan failed unexpectedly: {type(exc).__name__}: {exc}"
                )
                statuses.append("unavailable")
        else:
            ledger_notes.append(
                "Tier-1 mobsfscan skipped: no native android source "
                f"(searched {repo / 'android'})"
            )

        # --- Tier 2: bundled-secrets (ALWAYS; no build, no Docker). ----------
        try:
            t2 = scan_bundled_secrets(repo)
            findings.extend(t2.findings)
            statuses.append(t2.status)
            if t2.status != "ok":
                ledger_notes.append(
                    f"Tier-2 bundled-secrets {t2.status}: {t2.notes}"
                )
            else:
                notes_parts.append(f"bundled-secrets: {len(t2.findings)} finding(s)")
        except Exception as exc:  # noqa: BLE001 — never crash the dimension
            ledger_notes.append(
                f"Tier-2 bundled-secrets failed unexpectedly: {type(exc).__name__}: {exc}"
            )
            statuses.append("unavailable")

        # --- Tier 3a/3b: MobSF Docker static scan (flag-gated, off default). -
        if mobsf:
            found = find_debug_apk(repo, apk)
            if found is None and mobsf_build:
                # Tier 3b: the ONLY path that produces an APK. The tempdir MUST
                # outlive the Tier-3a collect_mobsf call (the built APK lives in
                # it), so the whole MobSF scan happens INSIDE this context.
                with scan_tempdir() as _mob_td:
                    out_apk = Path(_mob_td) / "built-debug.apk"
                    build_result: BuildResult = build_debug_apk_copy(
                        repo,
                        env=base_env,
                        out_apk=out_apk,
                        timeout_seconds=_BUILD_TIMEOUT,
                    )
                    if build_result.status == "ok" and build_result.apk_path:
                        found = build_result.apk_path
                        notes_parts.append("assembleDebug: built debug APK")
                    else:
                        ledger_notes.append(
                            "Tier-3b assembleDebug "
                            f"{build_result.status}: {build_result.notes}"
                        )
                        statuses.append(build_result.status)
                    if found is not None:
                        t3 = collect_mobsf(
                            found,
                            env=base_env,
                            image_ref=_MOBSF_IMAGE,
                            timeout_seconds=_MOBSF_TIMEOUT,
                        )
                        findings.extend(t3.findings)
                        statuses.append(t3.status)
                        if t3.status != "ok":
                            ledger_notes.append(
                                f"Tier-3a MobSF {t3.status}: {t3.notes}"
                            )
                        else:
                            notes_parts.append(
                                f"mobsf: {len(t3.findings)} finding(s)"
                            )
            elif found is not None:
                # Tier 3a over an existing / supplied APK (no build).
                t3 = collect_mobsf(
                    found,
                    env=base_env,
                    image_ref=_MOBSF_IMAGE,
                    timeout_seconds=_MOBSF_TIMEOUT,
                )
                findings.extend(t3.findings)
                statuses.append(t3.status)
                if t3.status != "ok":
                    ledger_notes.append(f"Tier-3a MobSF {t3.status}: {t3.notes}")
                else:
                    notes_parts.append(f"mobsf: {len(t3.findings)} finding(s)")
            else:
                # --mobsf requested but no APK and no --mobsf-build → no build.
                ledger_notes.append(
                    "Tier-3 MobSF requested but no existing APK found "
                    "(pass --mobsf-build to produce one); no build was run."
                )
                statuses.append("unavailable")
    except Exception as exc:  # noqa: BLE001 — absolute never-raise backstop
        return MobileScanResult(
            status="unavailable",
            findings=findings,
            notes=f"mobile composition failed: {type(exc).__name__}: {exc}",
            ledger_notes=ledger_notes
            + [f"Mobile dimension unavailable: {type(exc).__name__}: {exc}"],
        )

    # --- Overall status (mirror run_supabase's logic). ----------------------
    if statuses and all(s == "ok" for s in statuses):
        status: MobileStatus = "ok"
    elif any(s == "ok" for s in statuses):
        status = "partial"
    else:
        status = "unavailable"

    return MobileScanResult(
        findings=findings,
        status=status,
        notes="; ".join(notes_parts),
        ledger_notes=ledger_notes,
    )


@register_adapter("mobile")
def run(repo_path, detection):  # noqa: ANN001, ANN201 — registry signature
    """Per-stack registration marker (D-40).

    The HEAVY three-tier mobile composition runs as the dedicated cross-stack
    ``scan_runner.run_mobile`` step (mirroring the Phase 7 SCA + Phase 8 RLS
    steps), because the ``--mobsf`` / ``--mobsf-build`` / ``--apk`` flag gating
    sits ABOVE per-stack dispatch (the per-stack ``run`` has no access to the CLI
    flags). This registered entry exists so the detector + scope ledger SEE the
    ``mobile`` adapter; it returns no findings of its own — they all flow through
    the cross-stack step.
    """
    return []


__all__ = [
    "ADAPTER_CONFIG",
    "CONFIG",
    "BuildResult",
    "MobileScanResult",
    "MobileStatus",
    "build_debug_apk_copy",
    "collect_mobsf",
    "collect_mobsfscan",
    "find_debug_apk",
    "run",
    "run_mobile",
    "run_mobsfscan",
    "scan_bundled_secrets",
]
