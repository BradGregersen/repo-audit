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
| **Proven** — run against real repositories | SARIF adapter foundation · dependency/CVE scanning · SAST · stack-depth and test-integrity adapters · supply-chain and git-history secrets · CI/CD and IaC · architecture fitness and duplication · the verification layer · synthesis and prioritization · issue filing · Supabase/RLS runtime enforcement check (run once against a live production database — scope below) |
| **Fixture-tested** — never run against a live target | mobile pentest / APK scanning |
| **Incomplete** | The performance regression-finding pipeline |

Fixture-tested means the code exists and is tested against recorded fixtures but
has never been run against a real APK; findings from that path are unproven
against live targets. Everything in the Proven row has produced real findings on
real targets.

The RLS runtime enforcement check (`--rls-runtime`) was run once, on 2026-09-23,
against the live production Supabase project behind a real React Native app: 21
two-account probes across 17 tables found zero cross-tenant reads or writes, and
a forged cross-user insert was rejected by policy. That is a runtime assertion
about the client (anon/authenticated) path on the tables probed, not proof of RLS
correctness for unprobed tables, for the service-role path, or for policies added
after that date.

### Known limitations

These are known, unfixed, and worth knowing before you trust a report or point
the tool at a repository.

- **It runs the target's own code, with your environment.** Project tools (tsc,
  eslint, knip and the other npm project tools) resolve from the target's own
  `node_modules/.bin` first, and `--typed-detekt` (on by default) runs the
  target's `./gradlew`. Both run as you, with your full environment, including
  any tokens or credentials in it (for example `GH_TOKEN` or the
  `--rls-runtime` variables). Security scanners resolve only vendored or PATH
  binaries. The target's own `.repo-audit.yaml` can switch on DAST (a ZAP
  container spidering the URL it names), `live_url` web checks, CodeQL
  autobuild, and bring-your-own commercial scanner wrappers. That file is
  treated as consent, so scanning a repository executes its configuration. Only
  scan repositories you would run `npm install` in.
- **Trend diffing can mislabel fixes.** Findings match across scans on tool +
  rule + file + line. grype and osv-scanner report absolute paths
  (`/requirements.txt`, `file:///…`), so the CVEs fixed by a dependency upgrade
  can read as "vanished with file" rather than "resolved". Inserting a line
  above a finding reads as one resolved finding plus one new identical finding.
- **"What matters most" can show the wrong things.** Only corroborated or
  confirmed findings qualify. Low-severity inventory rows that carry no file can
  corroborate each other and fill the list. Single-tool candidates are left
  out, which includes every dependency CVE and committed-secret hit under
  `--no-agent` and in `fleet`. Candidates cap at major, so the header's
  blocker/critical count reads zero in those modes. Read the Security section,
  not only the headline list.

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
  into one prioritized report instead of raw tool dumps. The mobile-scanning path
  runs through the same pipeline but is fixture-tested only (see
  [Maturity](#maturity)).
- **Trend-aware.** Each scan diffs against the prior report (resolved / still
  present / vanished-with-file).

### What the report covers

A state report is written to the target repo at
`docs/state-reports/{repo}-state-report-{YYYY-MM-DD}.md` (with a JSON sidecar
beside it), organized into:

1. Executive summary + "what matters most" (prioritized findings — see
   [Known limitations](#known-limitations))
2. Scope ledger — what was scanned, skipped, or unavailable
3. Security & SAST
4. Architecture rot
5. Test integrity
6. Correctness & data/privacy — the static Supabase checks are proven; the
   opt-in **runtime** RLS enforcement check has one live run behind it (see
   [Maturity](#maturity) for what that does and does not cover)
7. Quality / footprint / docs — the performance regression-finding pipeline is
   incomplete and reports nothing useful yet
8. Process & backlog
9. Observability & runtime

Mobile/APK scanning is opt-in via `--mobsf` / `--apk` and is fixture-tested
only.

## What it does not do

- **It never modifies the repository it audits** — no code edits, no config
  changes, no commits, and no shipping build artifacts. Diagnostic builds, when
  they are needed at all, run in throwaway copies.
- **Inside the target repo it writes to exactly one location:**
  `docs/state-reports/`. Outside the target it also writes:
  - a vulnerability-database cache under `~/.cache/repo-audit/vuln-db/` (or
    `$XDG_CACHE_HOME/repo-audit/vuln-db/`), downloaded over the network on the
    first scan and advanced afterwards only by `--refresh-vuln-db`;
  - an SBOM into repo-audit's own `reports/` directory, on every scan;
  - per-scan temporary directories, which are cleaned up after the scan.
- **It is not fully offline by default.** Besides the first-run vuln-DB
  download, the default SAST pass fetches Semgrep rule packs over the network
  (`--no-sast` turns it off), and `--typed-detekt` (on by default) runs the
  target's own Gradle build (`./gradlew`) in a throwaway copy for any repo that
  has a `gradlew` (`--no-typed-detekt` turns it off). Running a target's build
  script executes that repo's code, so only scan repos you trust with it on.

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

Useful flags (all opt-in checks default **off**; most outward-facing or
expensive checks are gated — the exceptions are listed under
[What it does not do](#what-it-does-not-do)):

| Flag | Effect |
|------|--------|
| `--no-agent` | Skip the agent loop; deterministic-only report (offline / debugging). |
| `--agent-budget N` | Override the per-scan token cap (default 150,000). |
| `--uncapped` | Remove every agent and critic budget cap for this run; overrides `--agent-budget`; no effect with `--no-agent`. |
| `--refresh-coverage` | Invoke the test runner to produce fresh coverage when stale/missing. |
| `--refresh-vuln-db` / `--refresh-kev` | The only paths that advance the OSV/grype or CISA KEV snapshots. The vuln-DB is otherwise pinned after its first-run download; the KEV snapshot ships with repo-audit. |
| `--epss` | Fetch live EPSS scores (network egress). |
| `--rls-runtime` / `--rls-pgrls` | Runtime two-account RLS enforcement test / additive pgrls linter (Supabase). Static `splinter` is the always-on floor. |
| `--mobsf` / `--mobsf-build` / `--apk` | Static MobSF APK scan; `--mobsf-build` builds a debug APK with Gradle in a throwaway copy when none exists. |
| `--typed-detekt` / `--no-typed-detekt` | On by default. Runs detekt with type resolution by building the target's Kotlin in a throwaway copy via its own `./gradlew`; falls back to standalone detekt if the build fails. |
| `--no-sast` | Skip the Semgrep SAST pass (on by default; fetches Semgrep rule packs over the network). |
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
