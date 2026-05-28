"""Doctor / self-test entry points.

Phase 1 ships only the secret-lint self-test (D-08). The full ``arch
--doctor`` tool-presence probe lands in Phase 7.
"""
from repo_audit.doctor.self_test import run_secret_lint_self_test

__all__ = ["run_secret_lint_self_test"]
