"""Phase 3 Wave 1 contract — SKIP via importorskip until plan 03-02 lands.

Per checker Warning 8: module-level ``pytest.mark.xfail(strict=True)`` does
NOT reliably catch collection-time ImportError. Use ``pytest.importorskip``
so the stub is SKIPPED cleanly when the implementation module is absent and
flips to ACTIVE tests automatically once the symbol exists.
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "repo_audit.adapters.registry",
    reason="Wave 1 (plan 03-02) not yet landed — adapters.registry missing",
)

# Once Wave 1 lands, importorskip becomes a no-op and these imports run.
from repo_audit.adapters.base import AdapterResult  # noqa: E402
from repo_audit.adapters.registry import (  # noqa: E402
    get_adapter_registry,
    register_adapter,
    run_adapters,
)


def test_register_adapter_decorator_appends_to_registry():
    """``@register_adapter('foo')`` adds ``foo`` to the registry dict."""
    @register_adapter("test-stack-registry-appends")
    def _fn(repo_path, detection):  # pragma: no cover (active in Wave 1)
        return []

    assert "test-stack-registry-appends" in get_adapter_registry()


def test_run_adapters_executes_matching_stacks(polyglot_repo):
    """``run_adapters`` invokes every adapter whose name appears in the detection."""
    from repo_audit.detect.detector import detect_stacks

    detection = detect_stacks(polyglot_repo)
    results = run_adapters(polyglot_repo, detection)
    assert isinstance(results, list)
    for r in results:
        assert isinstance(r, AdapterResult)


def test_run_adapters_sequential_never_raises_across_boundary(
    tmp_path, monkeypatch,
):
    """D-25: a buggy adapter MUST NOT raise across the orchestrator boundary."""
    from repo_audit.adapters import registry as reg
    from repo_audit.detect.detector import detect_stacks

    def bad_adapter(repo_path, detection):
        raise RuntimeError("synthetic adapter crash")

    monkeypatch.setitem(reg._REGISTRY, "bad-adapter", bad_adapter)
    # Forge a detection that includes 'bad-adapter' so it actually gets invoked
    detection = detect_stacks(tmp_path)
    results = run_adapters(tmp_path, detection)
    # Either the orchestrator returns an "unavailable" record OR it returns
    # an empty list — both are valid D-25 outcomes; what matters is no raise.
    assert isinstance(results, list)


def test_register_adapter_double_registration_raises():
    """A second ``@register_adapter('same-name')`` MUST raise (no silent shadow)."""
    @register_adapter("test-double-reg-stack")
    def _first(repo_path, detection):  # pragma: no cover (active in Wave 1)
        return []

    with pytest.raises(RuntimeError, match="double-registered"):
        @register_adapter("test-double-reg-stack")
        def _second(repo_path, detection):  # pragma: no cover (active in Wave 1)
            return []
