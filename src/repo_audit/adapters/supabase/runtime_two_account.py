"""RLS-03 runtime two-account wrapper — the SOLE runtime emitter (Plan 08-04).

This module is the IDENTITY of Phase 8: the single collector in the entire tool
permitted to emit ``evidence_type="runtime"`` and to assert REAL cross-tenant
RLS enforcement. It does NOT reimplement the probe — it WRAPS the user's
existing ``scripts/audit/rls-two-account-test.mjs`` (Pitfall 7 — never
reimplement), which is value-blind (prints no secrets) and self-cleaning
(deletes its probe rows, signs out) by design. We preserve both properties and
route any tool output through redaction as defense-in-depth.

THE GATE (D-08-01) — the runtime test NEVER auto-runs:
  It runs ONLY when ``opted_in is True`` (the explicit ``--rls-runtime`` opt-in,
  gated upstream in Plan 05) AND all six required env-var NAMES resolve. Creds
  present WITHOUT the flag still does NOT run. In every not-run case: ZERO
  findings and NO enforcement language anywhere — the honest scope-ledger entry
  IS the disclosure (D-08-05).

THE EXIT -> EVIDENCE MAP (D-08-04) — the actually-executed exit code is the SOLE
source of runtime evidence:
  * 0 -> ONE ``evidence_type="runtime"`` finding asserting "RLS enforced
    cross-tenant on probed tables" (the ONLY place enforcement language is
    permitted — :func:`assert_verify_phrasing` EXEMPTS runtime), ``info``
    severity, ``confidence="confirmed"`` (NOT candidate).
  * 1 -> ONE runtime cross-tenant LEAK finding at ``severity="blocker"`` (the
    sanctioned NON-candidate critical/blocker — SCH-04's candidate rung-cap does
    NOT apply because the finding is runtime-evidenced, not candidate),
    ``dimension="security"``.
  * 2 -> ``unavailable`` (the script's setup/config-error exit).
  * -1 (node missing, the run_tool EXEC_FAILED sentinel) -> ``unavailable``.
  * -2 (timeout, the run_tool TIMED_OUT sentinel) -> ``timeout``.

VALUE-BLIND (T-08-14): the six credentials flow to the child ONLY via the run
env (never argv, never shell). The script is value-blind by design; the wrapper
additionally scrubs the BASE env of secret-NAMED keys before re-injecting the
six the script needs, and routes stdout/stderr through :func:`_redact_tail`
(<=2 KB) before any tail lands in notes. *_KEY/_PASSWORD/_SECRET names are never
logged. Never raises across its boundary.
"""
from __future__ import annotations

from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.resolution import resolve_tool
from repo_audit.adapters.supabase.verify_phrasing import (
    assert_verify_phrasing,
)
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.finding import Evidence, Finding

# The SIX env-var NAMES the user's script reads (rls-two-account-test.mjs). The
# gate requires ALL six present (by NAME) before the probe may run (D-08-01).
_REQUIRED_ENV_NAMES: list[str] = [
    "EXPO_PUBLIC_SUPABASE_URL",
    "EXPO_PUBLIC_SUPABASE_ANON_KEY",
    "AUDIT_TEST_USER_A_EMAIL",
    "AUDIT_TEST_USER_A_PASSWORD",
    "AUDIT_TEST_USER_B_EMAIL",
    "AUDIT_TEST_USER_B_PASSWORD",
]

# The user's existing script, relative to the repo root (D-08-02 — we INVOKE it,
# never reimplement the rls-two-account probe logic).
_SCRIPT_REL = Path("scripts") / "audit" / "rls-two-account-test.mjs"

_SOURCE_TOOL = "rls-two-account"
_DIMENSION = "security"

# Secret-NAMED suffixes scrubbed from the BASE env before re-injecting the six
# creds the script needs (mirrors refresh.py::_scrub_secrets discipline).
_SECRET_KEY_SUFFIXES: tuple[str, ...] = (
    "_TOKEN",
    "_KEY",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
)

# Tail cap for redacted stdout/stderr in notes (mirrors refresh.py M2 bound).
_TAIL_CAP: int = 2048


def _scrub_secrets(env: dict[str, str]) -> dict[str, str]:
    """Drop secret-NAMED keys from a copy of ``env`` (mirrors refresh.py).

    Conservative: any ``*_TOKEN`` / ``*_KEY`` / ``*_SECRET`` / ``*_PASSWORD`` /
    ``*_PASSWD`` goes. Returns a NEW dict; does not mutate the input.
    """
    return {
        k: v
        for k, v in env.items()
        if not any(k.upper().endswith(sfx) for sfx in _SECRET_KEY_SUFFIXES)
    }


def _redact_tail(text: str) -> str:
    """Truncate to ``_TAIL_CAP`` and apply the render-secret-lint redaction.

    Defense-in-depth at the child-process boundary (the script is already
    value-blind). A secret-lint hit becomes a redacted notice rather than a
    crash; never raises.
    """
    snippet = text[-_TAIL_CAP:] if len(text) > _TAIL_CAP else text
    try:
        from repo_audit.render.secret_lint import SecretsDetected, lint_buffer

        try:
            lint_buffer(snippet, buffer_name="rls_runtime_tail")
        except SecretsDetected as hits:
            return (
                f"[REDACTED: {len(snippet)} chars contained "
                f"{len(hits.hits)} potential secrets]"
            )
    except Exception:  # pragma: no cover — defensive
        pass
    return snippet


def _build_run_env(env: dict[str, str]) -> dict[str, str]:
    """Scrub the base env of secret-NAMED keys, then re-inject the six creds.

    The script self-loads its credentials from the process env by NAME (it does
    NOT use ``--env-file`` paths the wrapper cannot see), so the wrapper must
    set the six on the child env. We scrub the base first so unrelated
    secret-named host vars do not ride along, then add back exactly the six the
    script needs.
    """
    run_env = _scrub_secrets(env)
    for name in _REQUIRED_ENV_NAMES:
        if name in env:
            run_env[name] = env[name]
    return run_env


def _unavailable(notes: str) -> AdapterResult:
    return AdapterResult(
        status="unavailable",
        findings=[],
        notes=notes,
        source_tool=_SOURCE_TOOL,
        dimension=_DIMENSION,
    )


def _enforced_finding(stdout_tail: str) -> Finding:
    """Exit 0 -> the ONE sanctioned runtime enforcement assertion (D-08-04)."""
    return Finding(
        dimension=_DIMENSION,
        severity="info",
        evidence=Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=stdout_tail,
            parsed_value={"exit_code": 0, "verdict": "no_cross_tenant_leak"},
        ),
        evidence_type="runtime",  # the SOLE exemption from assert_verify_phrasing
        confidence="confirmed",
        recommendation=(
            "Two-account runtime test PASSED: RLS enforced cross-tenant on the "
            "probed tables — User B could neither read nor write User A's rows "
            "on the live Supabase (anon path)."
        ),
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_TOOL,
        rule_id="rls_runtime_enforced",
    )


def _leak_finding(stdout_tail: str) -> Finding:
    """Exit 1 -> a runtime cross-tenant LEAK at blocker (NON-candidate, D-08-04)."""
    return Finding(
        dimension=_DIMENSION,
        severity="blocker",  # runtime-evidenced => SCH-04 candidate cap N/A
        evidence=Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=stdout_tail,
            parsed_value={"exit_code": 1, "verdict": "cross_tenant_leak"},
        ),
        evidence_type="runtime",
        confidence="confirmed",
        recommendation=(
            "Two-account runtime test FAILED: a cross-tenant data leak was "
            "observed at runtime — User B read or wrote User A's data on the "
            "live Supabase. RLS is NOT being applied on at least one probed "
            "table. This is a confirmed runtime finding, not a candidate."
        ),
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_TOOL,
        rule_id="rls_cross_tenant_leak",
    )


def collect_runtime_two_account(
    repo: Path,
    *,
    opted_in: bool,
    env: dict[str, str],
    timeout_seconds: float,
) -> AdapterResult:
    """Gate, invoke, and map the user's two-account runtime RLS test.

    The SOLE ``evidence_type="runtime"`` emitter in the tool. Never auto-runs
    (D-08-01); wraps the user's existing value-blind self-cleaning script
    (D-08-02, never reimplemented); maps exit 0/1/2 -> enforced / LEAK / setup
    (D-08-04); emits zero enforcement language when not run (D-08-05); routes
    output through redaction (T-08-14). Never raises.

    Args:
        repo: the target repository root (cwd for the child; holds the script).
        opted_in: the explicit ``--rls-runtime`` opt-in (gated upstream Plan 05).
            ``False`` -> NOT run, even if all six creds are present (D-08-01).
        env: the environment mapping; must contain all six ``_REQUIRED_ENV_NAMES``
            for the gate to open.
        timeout_seconds: hard wall-clock bound for the child (T-08-17).

    Returns:
        ``AdapterResult``. ``ok`` with exactly one runtime finding on exit 0/1;
        ``unavailable`` (not-run gate / exit 2 / exec-failed / missing script /
        node absent / internal error) or ``timeout`` (-2). Never raises.
    """
    try:
        # 1. GATE (D-08-01) — never auto-run.
        if not opted_in:
            return _unavailable(
                "runtime RLS enforcement test not run (not opted in) — pass "
                "--rls-runtime to enable; presence of credentials alone never "
                "triggers it"
            )
        missing = [name for name in _REQUIRED_ENV_NAMES if not env.get(name)]
        if missing:
            return _unavailable(
                "runtime RLS enforcement test not run (no creds) — missing "
                f"env-var names: {', '.join(missing)}"
            )

        # 2. Locate the script + node. Either absent => unavailable, no probe.
        script = repo / _SCRIPT_REL
        if not script.is_file():
            return _unavailable(
                f"runtime test script not found in repo ({_SCRIPT_REL})"
            )
        node = resolve_tool("node", repo)
        if node is None:
            return _unavailable(
                "node not found (vendor + PATH miss) — cannot run the runtime "
                "two-account test"
            )

        # 3. INVOKE the existing script (D-08-02 — never reimplement). The six
        #    creds flow to the child ONLY via the scrubbed run env (never argv).
        run_env = _build_run_env(env)
        res = run_tool(
            [str(node), str(script)],
            env=run_env,
            cwd=repo,
            timeout_seconds=timeout_seconds,
        )

        # 5. Redact output tails BEFORE any tail lands in notes/snippet.
        stdout_tail = _redact_tail(res.stdout)
        stderr_tail = _redact_tail(res.stderr)

        # 4. MAP exit code (D-08-04).
        if res.returncode == TIMED_OUT:
            return AdapterResult(
                status="timeout",
                findings=[],
                notes=f"runtime two-account test exceeded {timeout_seconds:.0f}s",
                source_tool=_SOURCE_TOOL,
                dimension=_DIMENSION,
            )
        if res.returncode == EXEC_FAILED:
            return _unavailable(
                f"runtime two-account test could not be executed: {stderr_tail[:200]}"
            )
        if res.returncode == 0:
            findings = [_enforced_finding(stdout_tail)]
        elif res.returncode == 1:
            findings = [_leak_finding(stdout_tail)]
        elif res.returncode == 2:
            return _unavailable(
                f"runtime test setup/config error (exit 2): {stderr_tail[:200]}"
            )
        else:
            # Any other exit code is not a sanctioned verdict -> unavailable.
            return _unavailable(
                f"runtime test returned unexpected exit {res.returncode}: "
                f"{stderr_tail[:160]}"
            )

        # 6. CRIT-4 post-pass — runtime findings are EXEMPT, so this must NOT
        #    raise on the exit-0/exit-1 enforcement/leak messages. This is the
        #    structural proof that runtime is the sanctioned exemption.
        assert_verify_phrasing(findings)

        return AdapterResult(
            status="ok",
            findings=findings,
            notes=f"runtime two-account test executed (exit {res.returncode})",
            source_tool=_SOURCE_TOOL,
            dimension=_DIMENSION,
        )
    except Exception as exc:  # noqa: BLE001 — never raise across the boundary
        return _unavailable(
            f"runtime two-account test degraded: {type(exc).__name__}: "
            f"{str(exc)[:160]}"
        )


__all__ = ["collect_runtime_two_account"]
