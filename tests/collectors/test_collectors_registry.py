"""Registry tests. STRICT — lands in Plan 02-01b.

NOTE: test_all_stub_collectors_report_initial_or_implemented_status is
deliberately loose — it accepts BOTH 'unavailable' (stub) AND 'ok'
(Wave 1 implementation landed) so it remains green as Wave 1 plans land
their collector bodies one at a time. This test is a BOUNDARY CONTRACT
assertion: the registry returns one CollectorResult per collector and
each result has a valid CollectorStatus. The stub-vs-implementation
distinction is intentionally NOT pinned here; per-collector behavior is
tested in tests/collectors/test_{collector}.py.
"""
from repo_audit.collectors import get_registry, run_collectors
from repo_audit.collectors.base import CollectorResult


def test_registry_has_six_collectors_in_stable_order():
    names = [fn.__module__.rsplit(".", 1)[-1] for fn in get_registry()]
    assert names == [
        "git_cadence",
        "loc_inventory",
        "doc_presence",
        "todo_markers",
        "file_size_cap",
        "secret_detection",
    ]


def test_run_collectors_returns_six_results(tmp_path):
    repo = tmp_path / "x"
    repo.mkdir()
    results = run_collectors(repo, {})
    assert len(results) == 6
    for r in results:
        assert isinstance(r, CollectorResult)
        assert r.duration_ms >= 0.0


def test_run_collectors_swallows_collector_exceptions(monkeypatch, tmp_path):
    """D-25: a buggy collector must NOT raise across the orchestrator boundary."""
    from repo_audit.collectors import _REGISTRY

    def bad(repo_path, repo_index):
        raise RuntimeError("synthetic")

    monkeypatch.setattr("repo_audit.collectors._REGISTRY", _REGISTRY + [bad])
    results = run_collectors(tmp_path, {})
    assert any(r.notes.startswith("RuntimeError") for r in results)
    assert all(r.status in {"ok", "unavailable", "timeout", "partial"} for r in results)


def test_all_stub_collectors_report_initial_or_implemented_status(tmp_path):
    """Boundary contract: every registered collector returns a valid
    CollectorStatus. Accepts BOTH 'ok' (Wave 1 body landed) and
    'unavailable' (still a stub) so the test remains stable as Wave 1
    plans land collector bodies one at a time. This is the orchestrator
    boundary contract — per-collector status correctness is asserted in
    each collector's own test file (tests/collectors/test_{collector}.py).

    Per-collector status under empty tmp_path:
    - git_cadence (Plan 02-02): 'unavailable' on non-git path
    - loc_inventory (Plan 02-03): 'ok' (empty findings) or 'unavailable'
      (vendored scc binary missing)
    - secret_detection (Plan 02-04): 'ok' or 'partial' (gitleaks PATH)
    - doc_presence (Plan 02-05): 'ok' (4 absent findings emitted)
    - todo_markers (Plan 02-05): 'ok' (0 findings)
    - file_size_cap (Plan 02-05): 'ok' (0 findings, all under cap)
    - Until each Wave 1 plan lands: 'unavailable' from the stub
    """
    repo = tmp_path / "y"
    repo.mkdir()
    results = run_collectors(repo, {})
    statuses = {r.source_collector: r.status for r in results}
    valid_states = {"ok", "unavailable", "timeout", "partial"}
    for name in ("git_cadence", "loc_inventory", "doc_presence",
                 "todo_markers", "file_size_cap", "secret_detection"):
        assert name in statuses, f"collector {name} missing from registry results"
        assert statuses[name] in valid_states, (
            f"collector {name} reported invalid status {statuses[name]!r}; "
            f"expected one of {valid_states}"
        )
