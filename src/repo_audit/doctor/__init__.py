"""Doctor / self-test entry points.

Only the secret-lint self-test is implemented; a tool-presence probe for
``repo-audit --doctor`` is not yet implemented.
"""
from repo_audit.doctor.self_test import run_secret_lint_self_test

__all__ = ["run_secret_lint_self_test"]
