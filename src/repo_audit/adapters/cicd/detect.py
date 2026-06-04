"""Read-only CI/CD surface detection-and-degrade (Phase 13, Plan 01).

Mirrors :mod:`repo_audit.adapters.supabase.discovery` (``find_migrations``):
directory/glob discovery resolved at CALL time (no module-load caching — the
Phase 3 lesson), returning an empty list = the honest "no such files" signal that
drives the SAFE-08 / D-13-05 first-class ``unavailable`` degrade.

Three CI/CD surfaces are distinguished, each gating one tool path:

  * **workflows** (:func:`find_workflows`) — ``.github/workflows/*.yml|*.yaml``;
    gates zizmor + actionlint.
  * **Dockerfiles** (:func:`find_dockerfiles`) — ``Dockerfile`` / ``Dockerfile.*`` /
    ``*.Dockerfile`` anywhere except under ``node_modules``; gates hadolint
    (one invocation per file).
  * **IaC config** (:func:`find_iac_config`) — a CONSERVATIVE trigger (D-13-05 /
    Open Q1): Terraform (``*.tf`` / ``*.tf.json``), Helm (``Chart.yaml``),
    Kustomize (``kustomization.yaml|yml``), and CloudFormation template markers
    (``*.template.yaml|yml|json``); gates checkov. The conservative trigger
    avoids firing on a stray application ``*.yaml`` (which would drag every repo
    into a slow checkov scan for nothing).

:func:`detect_cicd_surface` summarizes which of the three surfaces are present so
callers can branch and tests can assert the present×absent matrix.

This module is PURE read-only filesystem: it never spawns a child process and
never writes. ``node_modules`` is excluded everywhere (mirrors ``discovery.py``).
T-13-01-PATH: filenames in a hostile target repo are untrusted input, but
``pathlib.glob`` only reads — there is no tool execution in this layer.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Workflow file globs under .github/workflows.
_WORKFLOW_GLOBS: tuple[str, ...] = ("*.yml", "*.yaml")

# Dockerfile globs (recursive). Dockerfile, Dockerfile.prod, api.Dockerfile, ...
_DOCKERFILE_GLOBS: tuple[str, ...] = ("**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile")

# CONSERVATIVE IaC trigger globs (D-13-05 / Open Q1). Terraform + Helm + Kustomize
# + CloudFormation template markers. A stray application *.yaml does NOT match.
_IAC_GLOBS: tuple[str, ...] = (
    "**/*.tf",
    "**/*.tf.json",
    "**/Chart.yaml",
    "**/kustomization.yaml",
    "**/kustomization.yml",
    "**/*.template.yaml",
    "**/*.template.yml",
    "**/*.template.json",
)

# Excluded directory segment (mirrors discovery.py line 82).
_EXCLUDED_PART = "node_modules"


@dataclass(frozen=True)
class CicdSurface:
    """Which CI/CD surfaces are present in a target repo (immutable summary).

    Each list is the (sorted, de-duplicated) set of discovered paths; an empty
    list is the honest "no such files" sentinel that drives the per-tool
    ``unavailable`` degrade (D-13-05). The ``has_*`` booleans are convenience
    predicates for callers / tests asserting the present×absent matrix.
    """

    workflows: tuple[Path, ...]
    dockerfiles: tuple[Path, ...]
    iac_config: tuple[Path, ...]

    @property
    def has_workflows(self) -> bool:
        return bool(self.workflows)

    @property
    def has_dockerfiles(self) -> bool:
        return bool(self.dockerfiles)

    @property
    def has_iac_config(self) -> bool:
        return bool(self.iac_config)

    @property
    def any_surface(self) -> bool:
        """True if ANY of the three surfaces is present."""
        return self.has_workflows or self.has_dockerfiles or self.has_iac_config


def find_workflows(repo: Path) -> list[Path]:
    """Discover GitHub Actions workflow files (read-only, call-time glob).

    Returns ``[]`` when ``repo/.github/workflows`` is not a directory (the honest
    "no workflows" sentinel); otherwise a sorted list of ``*.yml`` + ``*.yaml``
    files directly under it.

    Args:
        repo: the target repository root.

    Returns:
        Sorted list of workflow file paths, or ``[]``.
    """
    repo = Path(repo)
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    return sorted(p for g in _WORKFLOW_GLOBS for p in wf_dir.glob(g) if p.is_file())


def find_dockerfiles(repo: Path) -> list[Path]:
    """Discover Dockerfiles anywhere in the repo except under ``node_modules``.

    Matches ``Dockerfile``, ``Dockerfile.*`` (e.g. ``Dockerfile.prod``), and
    ``*.Dockerfile`` (e.g. ``api.Dockerfile``). Files under any ``node_modules``
    parent are EXCLUDED (a vendored dependency's Dockerfile is not the target's
    surface). Results are de-duplicated (the glob patterns can overlap) and
    sorted.

    Args:
        repo: the target repository root.

    Returns:
        Sorted, de-duplicated list of Dockerfile paths, or ``[]``.
    """
    repo = Path(repo)
    found = {
        p
        for g in _DOCKERFILE_GLOBS
        for p in repo.glob(g)
        if _EXCLUDED_PART not in p.parts and p.is_file()
    }
    return sorted(found)


def find_iac_config(repo: Path) -> list[Path]:
    """Discover IaC config files with a CONSERVATIVE trigger (D-13-05 / Open Q1).

    Matches Terraform (``*.tf`` / ``*.tf.json``), Helm (``Chart.yaml``),
    Kustomize (``kustomization.yaml|yml``), and CloudFormation template markers
    (``*.template.yaml|yml|json``). A stray application ``*.yaml`` is deliberately
    NOT a trigger — that keeps checkov (the slowest tool) from firing on every
    repo. Files under ``node_modules`` are excluded. De-duplicated + sorted.

    Args:
        repo: the target repository root.

    Returns:
        Sorted, de-duplicated list of IaC config paths, or ``[]``.
    """
    repo = Path(repo)
    found = {
        p
        for g in _IAC_GLOBS
        for p in repo.glob(g)
        if _EXCLUDED_PART not in p.parts and p.is_file()
    }
    return sorted(found)


def detect_cicd_surface(repo: Path) -> CicdSurface:
    """Summarize which of the three CI/CD surfaces are present (read-only).

    Resolves all three discovery globs at CALL time and packs them into an
    immutable :class:`CicdSurface`. Callers branch on the ``has_*`` predicates to
    decide which collectors to run vs. degrade to ``unavailable`` (the D-13-05
    first-class path); tests assert the present×absent matrix off this one call.

    Args:
        repo: the target repository root.

    Returns:
        A frozen :class:`CicdSurface` summary.
    """
    repo = Path(repo)
    return CicdSurface(
        workflows=tuple(find_workflows(repo)),
        dockerfiles=tuple(find_dockerfiles(repo)),
        iac_config=tuple(find_iac_config(repo)),
    )


__all__ = [
    "CicdSurface",
    "detect_cicd_surface",
    "find_dockerfiles",
    "find_iac_config",
    "find_workflows",
]
