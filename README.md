# Repo Audit

A pluggable repo health-scanning system. Point it at any repository and it runs a
comprehensive suite of troubleshooting and auditing tools — surfacing issues across
code quality, dependencies, security, configuration, and project hygiene.

## Goals

- **Plug into any repo** — language/framework agnostic where possible.
- **Comprehensive** — aggregate linters, type checkers, security scanners,
  dependency auditors, and structural checks behind one entry point.
- **Actionable** — produce a clear, prioritized health report rather than raw tool dumps.

## Status

Early scaffold. Architecture and tool integrations to be defined.

## Layout

```
src/        # scanner core and tool adapters
docs/        # design notes and architecture
```

## SAST (Semgrep) install

Semgrep (the SAST scanner, Phase 10) is invoked **only as a subprocess** on PATH
(via `resolve_tool` / `run_tool`) — it is never imported. Its transitive pins
(`click<8.2`, and for older versions `rich<13.6`) conflict with this project's
runtime deps (pgrls's `click>=8.2`, Typer's `rich>=14.0`), so Semgrep must be
installed in its **own isolated environment**, not co-resolved with the app:

```bash
# Preferred — isolated tool venv with `semgrep` on PATH:
uv tool install semgrep==1.163.0
# OR:
pipx install semgrep==1.163.0

# For local dev/CI that runs the SAST integration tests, the pin also lives in
# the isolated `sast` dependency-group (NOT [project].dependencies):
uv sync --group sast
```

The exact `semgrep==1.163.0` pin (D-10-01) is preserved for reproducibility.
