"""Phase 3 adapter registry + orchestrator (D-40 + D-24/D-25 mirror).

Each adapter package (``repo_audit.adapters.typescript``,
``repo_audit.adapters.python`` in Phase 6, etc.) imports
``register_adapter`` from here and applies it as a parametrised decorator
to its ``run(repo_path, detection) -> list[AdapterResult]`` function::

    @register_adapter("typescript-node")
    def run(repo_path, detection):
        ...

The registry is a ``dict[str, Callable]`` keyed by stack name. Double
registration raises ``RuntimeError`` so a typo in the second
``@register_adapter`` doesn't silently shadow the first.

The orchestrator ``run_adapters(repo_path, detection)`` iterates the
``DetectionResult.stacks`` list and dispatches each stack to its
registered adapter (if any). Stacks with no registered adapter are
SILENTLY SKIPPED — this is the D-40 graceful-degradation contract
(Phase 6 will land the Python and Kotlin adapters; the orchestrator
must not fail on a detection result that names a stack we haven't
implemented yet).

D-25 cross-boundary safety: a buggy adapter that raises ANY exception
inside its ``run()`` function MUST NOT propagate. The orchestrator wraps
each dispatch in try/except and maps exceptions to
``AdapterResult(status='unavailable', notes='<exc type>: <exc msg>',
source_adapter=<stack>)``. This is the same backstop pattern Phase 2's
``run_collectors`` uses for collectors.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from repo_audit.adapters.base import AdapterResult
from repo_audit.schema.detection import DetectionResult

AdapterFn = Callable[[Path, DetectionResult], list[AdapterResult]]

# Module-level registry. Keyed by stack name (the literal that
# DetectionResult.stacks[i].stack carries). Phase 6 adapters add their
# entries by importing this module and applying @register_adapter.
_REGISTRY: dict[str, AdapterFn] = {}


def register_adapter(name: str) -> Callable[[AdapterFn], AdapterFn]:
    """Decorator factory: register ``fn`` under ``name`` (D-40).

    Usage::

        @register_adapter("typescript-node")
        def run(repo_path, detection):
            ...

    Double registration is a hard error — a second ``@register_adapter``
    with the same name raises ``RuntimeError`` to fail loud rather than
    silently shadowing the first registration. Phase 3 plan 03-01a
    pinned the literal ``typescript-node`` as the only string the
    TypeScript adapter may use; an accidental second registration here
    (e.g. a refactor that re-imports) signals a real bug.
    """

    def _decorator(fn: AdapterFn) -> AdapterFn:
        if name in _REGISTRY:
            raise RuntimeError(
                f"Adapter {name!r} double-registered: a function is already "
                f"registered under this name. Each stack name may have at most "
                f"one adapter."
            )
        _REGISTRY[name] = fn
        return fn

    return _decorator


def get_adapter_registry() -> dict[str, AdapterFn]:
    """Return a SHALLOW COPY of the registry dict.

    Tests use this to assert presence (e.g.
    ``'typescript-node' in get_adapter_registry()``). Returning a copy
    means callers can't mutate the live registry by mistake; the
    decorator is the only sanctioned path to add entries.
    """
    return dict(_REGISTRY)


def run_adapters(
    repo_path: Path, detection: DetectionResult
) -> list[AdapterResult]:
    """Iterate ``detection.stacks`` and dispatch each to its registered adapter.

    D-24 sequential. D-25 never raises across the orchestrator
    boundary: any exception inside an adapter's ``run()`` becomes an
    ``AdapterResult(status='unavailable', notes=<exc>, source_adapter=<stack>)``
    record rather than propagating.

    Stacks with NO registered adapter (e.g. ``python`` before Phase 6
    lands the Python adapter) are silently skipped — this is the
    graceful-degradation contract that lets Phase 3 ship the TypeScript
    adapter against a multi-stack detection result without forcing the
    other adapters to ship in lockstep.
    """
    results: list[AdapterResult] = []
    for profile in detection.stacks:
        fn = _REGISTRY.get(profile.stack)
        if fn is None:
            # Stack detected but no adapter registered — silent skip per
            # D-40. The scope ledger will surface the absence elsewhere
            # (Phase 5 fleet roll-up) but the per-scan run does not fail.
            continue
        try:
            adapter_results = fn(repo_path, detection)
        except Exception as exc:  # noqa: BLE001 — D-25 cross-boundary backstop
            results.append(
                AdapterResult(
                    status="unavailable",
                    notes=f"{type(exc).__name__}: {exc}",
                    source_adapter=profile.stack,
                )
            )
            continue
        # Sanity: an adapter's run() returning something other than a list
        # of AdapterResult is also a bug we surface as unavailable rather
        # than letting it crash a downstream consumer.
        if not isinstance(adapter_results, list):
            results.append(
                AdapterResult(
                    status="unavailable",
                    notes=(
                        f"adapter {profile.stack!r} returned "
                        f"{type(adapter_results).__name__}, not list"
                    ),
                    source_adapter=profile.stack,
                )
            )
            continue
        results.extend(adapter_results)
    return results
