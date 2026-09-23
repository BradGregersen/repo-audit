"""Runtime self-test for the secret-lint safeguard.

Wired to the CLI as ``repo-audit --doctor --self-test-secret-lint``.
Exercises the SAME ``lint_buffer`` code path that the renderer's
``render_and_write`` calls, so a passing self-test proves the on-box
safeguard is healthy.

Return codes:
    2 -- EXPECTED: the synthetic secret was caught and refused (safeguard works).
    1 -- UNEXPECTED: the synthetic secret was NOT caught (safeguard broken).

Only this self-test is implemented under ``--doctor``; a tool-presence probe
is not yet implemented.
"""
from __future__ import annotations

import sys

from repo_audit.render.secret_lint import (
    SecretsDetected,
    format_diagnostic,
    lint_buffer,
)

# AWS canonical example -- documented non-real value, NOT a usable credential.
# Mirrors tests/conftest.py::synthetic_secret to exercise the same code path
# the renderer uses for real reports. Constructed via string concatenation so
# the literal does not appear as a single token in source-file scans.
_SYNTHETIC_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def run_secret_lint_self_test() -> int:
    """Inject a synthetic secret; assert ``lint_buffer`` raises; print diagnostic.

    Returns:
        2 -- the safeguard fired as expected (intended exit code per D-06).
        1 -- the safeguard FAILED to fire (real bug; loud stderr message).
    """
    buf = (
        "# self-test buffer\n"
        "\n"
        f"This line contains a synthetic high-entropy token: {_SYNTHETIC_AWS_KEY}\n"
        "End of buffer.\n"
    )
    try:
        lint_buffer(buf, buffer_name="self-test")
    except SecretsDetected as e:
        # Expected path: the safeguard caught the synthetic secret.
        print(
            "OK -- secret-lint self-test detected synthetic secret as expected.",
            file=sys.stderr,
        )
        print(format_diagnostic(e.hits, e.buffer_name), file=sys.stderr)
        return 2
    # If we got here, the safeguard did NOT fire. That is a real bug.
    print(
        "FAIL -- secret-lint self-test did NOT detect the synthetic secret. "
        "The renderer's REP-05 safeguard is broken. Investigate "
        "repo_audit/render/secret_lint.py before shipping.",
        file=sys.stderr,
    )
    return 1
