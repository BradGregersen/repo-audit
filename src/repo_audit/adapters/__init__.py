"""Phase 3 adapter package (D-37, D-40).

Re-exports the primitives for external consumers (cli.py, tests):

    * register_adapter, run_adapters, get_adapter_registry
    * AdapterResult, InvocationResult

Import side-effect: importing this package does NOT auto-register
individual adapters. ``cli.py`` (and tests that want to exercise the
TypeScript adapter) explicitly imports
``repo_audit.adapters.typescript`` to trigger TS registration.
Phase 6 will add ``repo_audit.adapters.python`` and
``repo_audit.adapters.kotlin`` the same way.

Why NOT auto-import every adapter here:
    Phase 3 ships the TS adapter only. Auto-importing every adapter
    would couple this package to Phase 6's adapter modules existing,
    which they don't yet. Keeping the import explicit at the consumer
    site lets Phase 6 ship adapters incrementally without touching
    this file.
"""
from repo_audit.adapters.base import AdapterResult, InvocationResult
from repo_audit.adapters.registry import (
    get_adapter_registry,
    register_adapter,
    run_adapters,
)

__all__ = [
    "AdapterResult",
    "InvocationResult",
    "get_adapter_registry",
    "register_adapter",
    "run_adapters",
]
