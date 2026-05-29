"""TypeScript adapter parser package marker.

Empty by design — Wave 1 (plan 03-02) lands this package marker but
does NOT ship any parser modules. The parser modules
(``tsc.py``, ``eslint.py``, ``knip.py``, ``lcov.py``) are added by
Wave 2 plans (03-03 and 03-04).

Why not stub the parsers here:
    The Wave 0b parser tests use ``pytest.importorskip`` against the
    target module path (e.g. ``"repo_audit.adapters.typescript.parsers.tsc"``).
    If a stub module landed at that path, ``importorskip`` would
    succeed and the tests would RUN against a stub that returns ``[]``,
    failing assertions like ``len(findings) >= 1``. Leaving the module
    files absent keeps the importorskip gate honest and the parser
    tests SKIPPED until the real implementations land.

The adapter ``run()`` in ``../__init__.py`` consumes the
``parser_dotted_path`` declared in ``adapter.yaml`` lazily via
``_load_parser``. When the target module is absent, ``_load_parser``
raises ``ModuleNotFoundError``; the adapter catches that and emits
``AdapterResult(status='unavailable')`` for the affected tool. That
fallback means importing this package today produces a working
adapter that yields four AdapterResults (one per declared tool), all
``status='unavailable'`` because their parsers haven't shipped yet.
Wave 2 then drops in the real parser modules and the same code path
flips to producing real Findings.
"""
