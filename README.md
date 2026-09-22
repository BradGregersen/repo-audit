# Repo Audit

A modular, polyglot **repo-health audit CLI**. Point `repo-audit` at a repository
and it auto-detects the stack, runs only the relevant checks, and writes a
faithful **state report** — the same dimensions and quality you'd produce by
hand, in minutes instead of days. Run it per-repo (`repo-audit scan`) or across a
whole directory of repos (`repo-audit fleet ~/Code`).

Exercised against a fleet spanning TypeScript/React Native, Kotlin/Android,
Python, C++, C#, Go, Rust, and Supabase — 9 language ecosystems, each
auto-detected from its manifest files.

## Maturity

Not every dimension is equally exercised. Where a capability stands today:

| Status | Capabilities |
|---|---|
| **Proven** — run against real repositories | SARIF adapter foundation · dependency/CVE scanning · SAST · stack-depth and test-integrity adapters · supply-chain and git-history secrets · CI/CD and IaC · architecture fitness and duplication · the verification layer · synthesis and prioritization · issue filing |
| **Fixture-tested** — never run against a live target | Supabase/RLS runtime enforcement check · mobile pentest / APK scanning |
| **Incomplete** | The performance regression-finding pipeline |

Fixture-tested means the code exists and is tested against recorded fixtures. It
has never touched a real database or a real APK. Findings from those two paths
are unproven against live targets; everything in the Proven row has produced
real findings on real repositories.

## Install and run

Requires Python 3.11–3.12.

```bash
git clone https://github.com/BradGregersen/repo-audit
cd repo-audit
uv sync                     # or:  pip install -e .

repo-audit scan .           # audit one repo  → state report + JSON sidecar
repo-audit detect .         # just show the detected stack(s)
repo-audit fleet ~/Code     # sweep every git repo under a directory
```

## What it does

- **Auto-detects the stack** from manifest files — TypeScript/Node, React Native,
  Expo, Kotlin/Android, Python, C++, C#/.NET, Go, Rust, and Supabase — and runs
  only the checks that apply.
- **Deterministic collectors produce the numbers; the AI never invents them.**
  Every finding is tagged with an evidence type (`live`, `static`, `unavailable`,
  `failed`) and a confidence level. A faithfulness gate strips any number the
  agent didn't get from a collector.
- **Aggregates many tools behind one entry point** — linters, type checkers,
  SAST/SCA security scanners, architecture and quality probes — and merges them
  into one prioritized report instead of raw tool dumps. The RLS/data-privacy and
  mobile-scanning paths run through the same pipeline but are fixture-tested only
  (see [Maturity](#maturity)).
- **Trend-aware.** Each scan diffs against the prior report (resolved / still
  present / vanished-with-file).

### What the report covers

A state report is written to the target repo at
`docs/state-reports/{repo}-state-report-{YYYY-MM-DD}.md` (with a JSON sidecar
beside it), organized into:

1. Executive summary + "what matters most" (prioritized, confirmed findings)
2. Scope ledger — what was scanned, skipped, or unavailable
3. Security & SAST
4. Architecture rot
5. Test integrity
6. Correctness & data/privacy — the static Supabase checks are proven; the
   **runtime** RLS enforcement check is fixture-tested only
7. Quality / footprint / docs — the performance regression-finding pipeline is
   incomplete and reports nothing useful yet
8. Process & backlog
9. Observability & runtime

Mobile/APK scanning is opt-in via `--mobsf` / `--apk` and is likewise
fixture-tested only.

## What it does not do

- **It never modifies the repository it audits** — no code edits, no config
  changes, no commits, and no shipping build artifacts. Diagnostic builds, when
  they are needed at all, run in throwaway copies.
- **It writes to exactly one location:** `docs/state-reports/` inside the target
  repo. Nothing else on your disk is touched.

## Install (detail)

Requires Python 3.11–3.12. [`uv`](https://docs.astral.sh/uv/) is recommended.

```bash
# From a local clone:
uv tool install --editable .
# OR:
pipx install --editable .
```

Both create an isolated environment with the `repo-audit` shim on PATH. The Claude
Code CLI binary is bundled with the Agent SDK — no separate install — and the
tool reuses your existing Claude Code auth.

Per-stack tools (tsc, eslint, ruff, mypy, detekt, gradle, gitleaks,
osv-scanner, grype, etc.) are discovered on PATH and skipped with an
`unavailable` evidence tag when absent. The `scc` LOC counter ships vendored.

## Usage

```bash
repo-audit scan [PATH]      # Scan one repo → state report + JSON sidecar (defaults to cwd)
repo-audit detect [PATH]    # Show auto-detected stack(s) without a full scan
repo-audit fleet DIR        # Sweep every .git child of DIR → triage dashboard
repo-audit issues [PATH]    # File confirmed findings as GitHub issues (gated)
```

Run `repo-audit` with no arguments for help.

### `repo-audit scan`

Runs the full pipeline and writes the report pair into the target repo's
`docs/state-reports/`. The Claude Agent loop narrates and classifies severity
between the deterministic collection and render steps.

Useful flags (all opt-in checks default **off**; everything outward-facing or
expensive is gated):

| Flag | Effect |
|------|--------|
| `--no-agent` | Skip the agent loop; deterministic-only report (offline / debugging). |
| `--agent-budget N` | Override the per-scan token cap (default 150,000). |
| `--refresh-coverage` | Invoke the test runner to produce fresh coverage when stale/missing. |
| `--refresh-vuln-db` / `--refresh-kev` | The only paths that advance the pinned OSV/grype or CISA KEV snapshots. Scans are otherwise pinned/offline. |
| `--epss` | Fetch live EPSS scores (network egress). |
| `--rls-runtime` / `--rls-pgrls` | Runtime two-account RLS enforcement test / additive pgrls linter (Supabase). Static `splinter` is the always-on floor. |
| `--mobsf` / `--mobsf-build` / `--apk` | Static MobSF APK scan; `--mobsf-build` is the only path that triggers a Gradle diagnostic build (in a throwaway copy). |
| `--no-sast` | Skip the Semgrep SAST pass (on by default). |
| `--mutation` | Opt-in StrykerJS mutation testing (slow; 30-min cap; never fleet-wide). |
| `--e2e` / `--fuzz` | Run existing E2E / fuzz suites if present (never auto-authored). |
| `--qd-build` | Diagnostic Metro bundle for RN bundle-size measurement (throwaway copy). |

Exit codes: `0` success (including every agent fallback mode — a deterministic
report still ships), `2` secret-lint refused, `3` completion-honesty refused.

### `repo-audit fleet`

Discovers every immediate `.git` child of `DIRECTORY`, re-scans each one fresh
and sequentially, and aggregates the per-repo sidecars into a triage dashboard:

```
reports/fleet-{YYYY-MM-DD}.json            # versioned contract
reports/fleet-dashboard-{YYYY-MM-DD}.md    # triage view (worst-health-first)
```

(Written into repo-audit's own gitignored `reports/`.) Failed scans become
dashboard rows, never aborts. Deterministic by default — pass `--with-agent` for
per-repo AI narration (avoid fleet-wide unless you want cost × N).

### `repo-audit issues`

Reads the most-recent state-report sidecar, drafts confirmed-only issues
(critical/blocker solos + per-dimension rollups), dedups against open issues,
shows a dry-run of exactly what would be filed, and files **nothing** until you
answer `y`. Filing — `gh issue create` with an idempotent `repo-audit` label —
is the only outward write the tool performs. `--yes` skips the gate for CI.

## Configuration

Zero-config by default — each detected stack brings sensible thresholds. Drop a
`.repo-audit.yaml` in a target repo to override thresholds, exclusions, or
severity.

## SAST (Semgrep) install

Semgrep (the SAST scanner) is invoked **only as a subprocess** on PATH (via
`resolve_tool` / `run_tool`) — it is never imported. Its transitive pins
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

The exact `semgrep==1.163.0` pin is preserved for reproducibility.

## Development

```bash
uv sync                       # install dev deps
uv run pytest                 # full suite; finishes in minutes
uv run pytest -m integration  # just the live-binary tests
```

Tech stack: Python 3.11+, [Typer](https://typer.tiangolo.com/) CLI,
[pydantic](https://docs.pydantic.dev/) models,
[Jinja2](https://jinja.palletsprojects.com/) report templates,
[pygit2](https://www.pygit2.org/) for git cadence, and the
[Claude Agent SDK](https://pypi.org/project/claude-agent-sdk/) for orchestration.
See `CLAUDE.md` for the full per-layer technology rationale.
