<!-- GSD:project-start source:PROJECT.md -->
## Project

**Repo Audit**

A modular, polyglot repo-health tool that auto-detects a repository's stack and runs only the relevant checks, generating a state report comparable to the ones the user already writes by hand. Built first for the user's own fleet of ~20 repos spanning TypeScript/React Native, Kotlin/Android, Python, C++, C#, and more. The CLI (`arch`) runs per-repo (`repo-audit scan`) or across a directory of repos (`repo-audit fleet ~/Code`).

**Core Value:** Generate a faithful state report for any of my repos — same dimensions and quality as the ones I wrote by hand — in minutes not days, regardless of language.

### Constraints

- **Tech stack**: Python for the tool itself — best fit for orchestration, subprocess, parsing, and rich AI SDK. Cross-platform via existing `.venv` patterns.
- **AI runtime**: Claude Agent SDK (Python). Latest SDK API to be consulted when implementing the orchestration phase; do not infer from training data.
- **Distribution**: Local clone + pipx/uv install of `arch` CLI. No PyPI publish.
- **Output convention**: State reports written into the target repo at `docs/state-reports/{repo}-state-report-{YYYY-MM-DD}.md` so reports live with their subject and are version-controlled there. JSON fleet artifacts collect in `repo-audit/reports/` (gitignored).
- **Config**: Zero-config defaults per detected stack; optional `.repo-audit.yaml` in a target repo overrides thresholds/exclusions/severity.
- **Read-only**: The tool never writes to a target repo outside of `docs/state-reports/`, never modifies code or config, never runs builds that produce shipping artifacts (only diagnostic builds where needed).
- **Reproducibility**: Metrics are produced by deterministic collectors; the AI orchestrator interprets them but never invents numbers. Every finding tags evidence type and confidence.
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

## Overview
## Per-Layer Recommendations
### 1. Packaging & Distribution — `uv` + `pyproject.toml` + `pipx`-compatible entry point
| Recommendation | Version | Rationale | Confidence |
|----------------|---------|-----------|------------|
| **`uv`** (Astral) for project management, lockfile, venv, Python install | `>=0.5` | 10–100× faster than Poetry, single binary replaces pyenv+virtualenv+pip+pip-tools. Native `uv build` / `uv publish` since 0.4 means we lose nothing by skipping Poetry. Has become the default in 2026. | HIGH |
| **`pyproject.toml`** with PEP 621 `[project]` metadata + `[project.scripts] repo-audit = "repo_audit.cli:app"` | PEP 621 | Standard, tool-agnostic. Works with uv, pip, pipx, and any future packaging manager. | HIGH |
| **`hatchling`** as build backend | latest | Default uv backend, no quirks, supports editable installs cleanly. Avoid `setuptools` (legacy footguns) and `poetry-core` (couples build to Poetry tooling we're not using). | HIGH |
| **Install path:** `pipx install --editable .` from local clone, or `uv tool install --editable .` | — | Both create an isolated venv with the `arch` shim on PATH. `uv tool` is the newer/faster path; `pipx` is what most users already have. Support both in README. | HIGH |
### 2. CLI Framework — **Typer 0.26.2**
| Library | Verdict | Reason |
|---------|---------|--------|
| **Typer** | **Use** | Built on Click by the FastAPI author. Type-hint-driven; commands are just annotated functions. Auto-help, auto-completion, validation come free. Reads as plain Python, which matters because we'll have many `arch` subcommands (`scan`, `fleet`, `detect`, `report`, `init`). |
| Click | Don't reach for | Solid, but Typer is a strict superset for our use case. The extra decorator boilerplate buys nothing we need. Only switch if we hit a Typer wall (we won't). |
| argparse | No | Acceptable for one-shot scripts, painful for nested subcommands with shared options. |
| Fire / docopt | No | Magic-based / docstring-parsed CLIs are harder to refactor. |
### 3. Claude Agent SDK — **`claude-agent-sdk` 0.2.87** (verified on PyPI 2026-05-23)
| Item | Value |
|------|-------|
| PyPI package | `claude-agent-sdk` |
| Latest version | `0.2.87` (released 2026-05-23) |
| Python | `>=3.10` |
| Install | `uv add claude-agent-sdk` (or `pip install claude-agent-sdk`) |
| Bundles | The Claude Code CLI binary is auto-bundled; no separate install |
| Auth | Uses Claude Code CLI's existing auth (the user is already authed since they run Claude Code) |
- `query()` — fire-and-forget async generator for one-shot prompts
- `ClaudeSDKClient` — bidirectional client; the one we need for custom tools and hooks
- `@tool(name, description, schema)` — decorator that wraps an async function as an MCP tool
- `create_sdk_mcp_server(name, version, tools=[...])` — bundles our tools as an **in-process** MCP server (no subprocess overhead — this is the right pattern for us, since our tools are pure Python collectors)
- `ClaudeAgentOptions(mcp_servers=..., allowed_tools=...)` — config object
- Message types: `AssistantMessage`, `UserMessage`, `SystemMessage`, `ResultMessage`
- Blocks: `TextBlock`, `ToolUseBlock`, `ToolResultBlock`
# repo_audit/collectors/git_cadence.py
# repo_audit/agent.py
### 4. Git Interaction — **`pygit2` 1.19.2** (with subprocess fallback for `git diff --stat` cases)
| Library | Verdict | Reason |
|---------|---------|--------|
| **`pygit2`** | **Primary** | Libgit2 binding, ~10× faster than GitPython for log walks (which is most of what we do for cadence). Wheels available for Linux/macOS/Windows x86-64 + ARM64 — no compilation. The `Repository.walk(head.target, GIT_SORT_TIME)` loop is exactly what cadence metrics need. |
| GitPython | Don't use | Spawns a `git` subprocess for every operation. Workable for one-off scripts; awful when we're scanning 20 repos and walking thousands of commits each. |
| `subprocess` + `git log --format=...` | **Fallback** | Use only for operations pygit2 makes harder than they should be (e.g., `git log --numstat` for churn-per-file, `git blame --line-porcelain` if we ever need it). Wrap in our subprocess helper (next section) so timeouts and parsing are uniform. |
| `dulwich` | No | Pure-Python git, slower than pygit2 with no upside for us. |
### 5. Subprocess Orchestration — `subprocess.run` with mandatory timeout + reader threads
| Library | Verdict | Reason |
|---------|---------|--------|
| **Stdlib `subprocess`** wrapped in our own helper | **Use** | Battle-tested. The deadlock is the pipe-buffer-fills problem, solved by draining stdout/stderr in threads OR using `Popen.communicate(timeout=...)` for bounded output. |
| `sh` library | No | Cute API, hides what's happening, harder to debug when tools misbehave. |
| `anyio` / `trio` async subprocess | Only if we go async-wide | Worth considering only because the Agent SDK is already async — there's a case for running collectors concurrently under one event loop. But mixing threaded readers with asyncio subprocess is error-prone. **Decision: start with sync `subprocess` in a `ThreadPoolExecutor`. Reassess only if scan latency is a problem.** |
| `plumbum` | No | Same hiding-stuff complaint as `sh`. |
- Always `shell=False`, command as a list.
- Always pass an explicit `timeout` (default 60s per collector; long-running gradle gets a per-adapter override).
- Catch `TimeoutExpired`, escalate `SIGTERM` → wait 5s → `SIGKILL`.
- Return a `ToolResult` even on failure; never raise. Adapter decides what counts as "unavailable" vs. "failed".
### 6. LOC / File Counting — **`scc` (vendored Go binary)** as primary; pure-Python walker for fallbacks
| Tool | Verdict | Reason |
|------|---------|--------|
| **`scc`** (boyter, Go) | **Primary** | ~3× faster than tokei (2026 benchmark: 23 ms vs 74 ms on the same corpus), supports complexity + COCOMO, dedupes files, has JSON output (`-f json`). Single static binary — drop in `vendor/scc/` per OS-arch, no install dance. |
| `tokei` (Rust) | Acceptable alt | Also fast and accurate; some people prefer its language taxonomy. Fine as a fallback if scc misclassifies. |
| `cloc` (Perl) | No | 20× slower than tokei; Perl runtime dependency annoying on minimal systems. |
| `pygount` | No | Pure-Python; orders of magnitude slower than scc/tokei, and we don't gain anything since both pure-Go binaries are easier to ship. |
| Roll-our-own with `pathlib` + line iterators | **Use only for `find files larger than X bytes` checks** | Don't reinvent comment-aware line counting. Do reinvent "list files >N KB" — that's literally `path.stat().st_size`. |
### 7. Stack Detection — **Manifest-file rules; do NOT vendor github-linguist**
| Approach | Verdict | Reason |
|----------|---------|--------|
| **Manifest-file detection** (our own rule table) | **Primary** | We don't need the 600-language tail. We need ~12 stacks (TS, RN, Kotlin/Android, Python, C#, C++, Rust, Go, Supabase, Expo, etc.). A YAML table mapping `{file_glob → stack_tag}` plus priority rules (e.g., `app.json` + `package.json` → React Native, not just Node) gives us higher precision than linguist's vendor-file heuristics. |
| `enry` / `go-enry` | Maybe later | Go port of linguist, faster, has Python bindings in development but not stable. Worth revisiting if our manifest rules become unwieldy. |
| `ghlinguist` (Ruby wrapper) | No | Requires Ruby + linguist gem on the user machine. Friction we don't need. |
| `douban/linguist` (Python clone) | No | Stale, last commit years old. |
| `scc`'s language detection | **Reuse** | scc already tells us per-file language counts. Use scc output as the LOC-by-language signal; use our manifest table as the "what stack patterns apply" signal. They answer different questions. |
### 8. Tool Output Parsing — Per-tool adapters; **SARIF where available**, JSON otherwise
| Format | Tools that emit it | Recommendation |
|--------|---------------------|----------------|
| **SARIF 2.1** | Ruff (`--output-format=sarif`), ESLint (via `@microsoft/eslint-formatter-sarif`), Semgrep, CodeQL, Bandit, many others | **Preferred when offered.** Write one SARIF→finding adapter; reuse across tools. OASIS standard, well-documented, every cloud uses it. Caveat: Ruff's SARIF output omits autofix info ([issue #19962](https://github.com/astral-sh/ruff/issues/19962)) — if we need autofix details, use Ruff's native JSON. |
| **JSON (tool-native)** | `ruff --output-format=json`, `tsc --listFiles --pretty false`, `eslint --format=json`, `pytest --json-report`, `jest --json`, `coverage json` | Use when SARIF isn't available or strips info we need. One adapter per tool. |
| **JUnit XML** | gradle test, pytest `--junitxml`, kover XML coverage | Use `defusedxml` (not stdlib `xml.etree.ElementTree`) for XML parsing — protects against XXE etc. when reading repo-provided files. |
| **Plain text / stderr** | TypeScript `tsc` errors when `--pretty true`; some legacy tools | Last resort. Regex-parse with `re.compile`, document the pattern, version-pin the tool we're parsing. |
### 9. Schema & Config — **pydantic 2.x** + **ruamel.yaml 0.18+**
| Library | Version | Use |
|---------|---------|-----|
| **pydantic** | `>=2.9` | All internal models: `Finding`, `ToolResult`, `StackDetection`, `ScanReport`, fleet roll-up rows, per-collector return payloads. Strict typing means the LLM can't smuggle invented fields past us. Use `model_validate()` for loading user YAML config. |
| **ruamel.yaml** | `>=0.18` | Loading `.repo-audit.yaml`. **Round-trip mode preserves comments and key order** — important because (a) when we generate a starter config via `repo-audit init`, it should have comments explaining options, and (b) if we ever write modified configs back, we don't blow away the user's notes. |
| PyYAML | — | **Avoid.** Drops all comments on load (0% round-trip preservation vs 100% for ruamel). Acceptable only for one-direction loads of files we'll never write back; we don't have a use case that justifies the second dependency. |
| `strictyaml` | — | No. Idiosyncratic subset of YAML, fights pydantic. |
| `tomllib` (stdlib, 3.11+) | builtin | For reading target-repo `pyproject.toml` during stack detection. Read-only is the only thing stdlib offers — perfect fit. |
### 10. Markdown Rendering — **Jinja2 3.1** for the state report template
| Approach | Verdict | Reason |
|----------|---------|--------|
| **Jinja2** | **Use** | The user's hand-written reports are long and structured (7 dimensions, deltas vs prior, per-finding tables). A template separates "what the report looks like" from "what the data is" — important because the report shape will be iterated on. Conditionals (`{% if prior_report %}...{% endif %}`), loops over findings, custom filters (`{{ severity \| severity_emoji }}`) all help. |
| f-strings | Use only for one-liners | Embedding a 400-line report template in a Python module via triple-quoted f-strings is reviewable for a week and then a nightmare. |
| `mdformat` | Use as post-step | Run rendered output through `mdformat` to normalize whitespace, table alignment, etc. Keeps diffs clean across runs. |
| LLM writes the whole markdown | **Partially** | The agent writes the narrative paragraphs ("This repo's cadence trend is...") and slots them into a Jinja template. **Do not let it format tables or headers** — keeps the structure stable across reports for diffing. |
### 11. Testing the Tool — pytest + Typer's `CliRunner` + `pytest-subprocess`
| Library | Use |
|---------|-----|
| **pytest** `>=8` | Test runner |
| **`typer.testing.CliRunner`** | Invoke CLI commands in-process without `subprocess.run` — fast, capturable stdout/stderr, isolated filesystem fixture (`runner.isolated_filesystem()`). |
| **`pytest-subprocess`** | Mock the *external* tools we shell out to (tsc, eslint, gradle). Register canned `(stdout, stderr, returncode)` per command. Far easier than `unittest.mock.patch("subprocess.run")` for `Popen` patterns. |
| **`pytest-cov`** | Coverage. Standard. |
| **fixtures: `tmp_path` + a `fake_repo` factory** | Build minimal fake repos in `tmp_path` with seeded git history (use pygit2 to seed commits with controlled timestamps) and manifest files. Test detection + collectors end-to-end without touching the user's real fleet. |
## Installation (Complete)
# Recommended path (uv)
# Install the tool itself
# OR
- `scc` (vendored per-OS; resolve at runtime)
- Per-adapter tools (tsc, eslint, gradle, ruff, pytest, etc.) — discovered on PATH or skipped with `evidence_type: unavailable`
## What NOT to Use
| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `anthropic` SDK (the legacy one) for the agent loop | That's the low-level chat-completions client. It can call tools but does not implement the Claude Code agent loop, context management, or built-in tools. | `claude-agent-sdk` |
| `claude-code-sdk` (old name) | Renamed to `claude-agent-sdk` in late 2025. Package still resolves but is a redirect/deprecated. | `claude-agent-sdk` |
| `GitPython` | Subprocess-per-call overhead; will dominate scan time at scale. | `pygit2` + occasional `subprocess` for niche `git log` shapes |
| `PyYAML` | Strips all comments, no round-trip support. | `ruamel.yaml` |
| Poetry (for a new project) | Slower, more invasive, no longer differentiated on publishing since uv 0.4. | `uv` |
| `setuptools` build backend | Legacy footguns around src-layout, editable installs, dynamic versioning. | `hatchling` |
| `cloc` | 20× slower than tokei, ~60× slower than scc. Perl dependency. | `scc` (or `tokei` as fallback) |
| `pygount` | Pure-Python LOC counting — orders of magnitude slower than scc. | `scc` |
| `sh` / `plumbum` for subprocess | Hide what's happening; harder to debug subprocess pathologies (hangs, large output, exit code semantics). | Stdlib `subprocess` wrapped in our own helper |
| `xml.etree.ElementTree` for parsing third-party XML (JUnit, kover) | XXE/billion-laughs vulnerable on hostile input. | `defusedxml` |
| `shell=True` in subprocess calls | Injection risk + shell-quoting complexity. | `shell=False`, command as `list[str]` |
| `Click` directly | Fine, but Typer wraps Click and removes ~60% of the decorator noise. | `Typer` (you get Click underneath for free if you ever need it) |
| Letting the LLM compute numbers | Reproducibility dies; trend deltas become unreliable. | Deterministic collectors; LLM only narrates + classifies severity. |
| Letting the LLM author the full markdown unchecked | Section headers, table shapes, dimension order drift across runs → breaks diff-ability. | Jinja template fixed structure; LLM fills narrative slots. |
## Version Compatibility Notes
| Combo | Note |
|-------|------|
| `claude-agent-sdk` 0.2.87 + Python 3.10 | Works; Python 3.11+ recommended for `tomllib` |
| `pygit2` 1.19.2 + Python 3.11–3.14 | Wheels available; no libgit2 compilation needed on Linux/macOS/Windows |
| `pydantic` 2.x + `ruamel.yaml` 0.18 | Use `model_validate(dict)` after loading YAML; no integration package needed |
| `Typer` 0.26.2 + `rich` 14.0 | Rich is a peer dep; Typer auto-detects and uses it for help/tracebacks |
| `scc` vendored binaries | Verify license headers (MIT) stay shipped alongside the binary |
## Open Questions for the Roadmap
## Sources
- [Claude Agent SDK for Python on PyPI](https://pypi.org/project/claude-agent-sdk/) — version 0.2.87 verified 2026-05-23
- [anthropics/claude-agent-sdk-python on GitHub](https://github.com/anthropics/claude-agent-sdk-python) — `@tool`, `create_sdk_mcp_server`, `ClaudeSDKClient` API verified
- [Agent SDK reference – Python (Claude API Docs)](https://platform.claude.com/docs/en/agent-sdk/python)
- [Typer on PyPI](https://pypi.org/project/typer/) — version 0.26.2 verified 2026-05-27, Python 3.10–3.14
- [pygit2 on PyPI](https://pypi.org/project/pygit2/) — version 1.19.2, wheels for linux/macos/windows x86-64 + arm64
- [uv vs Poetry 2026 comparison – pydevtools](https://pydevtools.com/handbook/explanation/how-do-uv-and-poetry-compare/) — 10–100× speed delta confirmed
- [scc benchmarks – boyter/scc](https://github.com/boyter/scc) — 23 ms vs tokei's 74 ms on 2026 benchmark
- [Performance: pygit2 vs subprocess git – libgit2/pygit2 #752](https://github.com/libgit2/pygit2/issues/752) — pygit2 dominant for log walks
- [ruamel.yaml on PyPI](https://pypi.org/project/ruamel.yaml/) — round-trip comment preservation verified
- [Ruff configuration docs](https://docs.astral.sh/ruff/configuration/) — supports `concise|full|json|json-lines|junit|grouped|github|gitlab|pylint|rdjson|azure|sarif` output formats
- [Ruff SARIF autofix omission – astral-sh/ruff #19962](https://github.com/astral-sh/ruff/issues/19962) — known caveat
- [SARIF v2.1 OASIS specification](https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html) — interoperability standard
- [pytest-subprocess (Simon Willison TIL)](https://til.simonwillison.net/pytest/pytest-subprocess) — subprocess mocking pattern
- [Rich on PyPI](https://pypi.org/project/rich/) — version 14.x, released April 2026
- [Packaging Python CLI apps with uv – thisDaveJ](https://thisdavej.com/packaging-python-command-line-apps-the-modern-way-with-uv/) — `[project.scripts]` + `uv tool install` pattern
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, or `.github/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
