# Third-party notices

repo-audit itself is released under the MIT License (see [`LICENSE`](LICENSE)). This file lists
the third-party software and data that repo-audit ships, depends on, runs, or downloads, and the
terms each comes under.

## 1. Vendored in this repository (redistributed)

| Name | Version | Upstream | License | License copy | Checksums |
|---|---|---|---|---|---|
| grype | 0.112.0 | https://github.com/anchore/grype | Apache-2.0 | `src/repo_audit/vendor/grype/LICENSE-grype.txt` | `src/repo_audit/vendor/grype/SHA256SUMS.txt` |
| syft | 1.45.0 | https://github.com/anchore/syft | Apache-2.0 | `src/repo_audit/vendor/syft/LICENSE` | `src/repo_audit/vendor/syft/SHA256SUMS.txt` |
| osv-scanner | 2.3.8 | https://github.com/google/osv-scanner | Apache-2.0 | `src/repo_audit/vendor/osv-scanner/LICENSE-osv-scanner.txt` | `src/repo_audit/vendor/osv-scanner/SHA256SUMS.txt` |
| scc | 3.7.0 | https://github.com/boyter/scc | MIT | `src/repo_audit/vendor/scc/LICENSE-scc.txt` | `src/repo_audit/vendor/scc/SHA256SUMS.txt` |

scc has a directory for each of four platforms (linux-x86_64, linux-arm64, macos-x86_64,
macos-arm64). Only the linux-x86_64 build is in the repository today; the other three are
placeholders, listed as pending in `SHA256SUMS.txt`.

None of these upstreams ships a NOTICE file.

**CISA Known Exploited Vulnerabilities (KEV) snapshot** at `src/repo_audit/vendor/kev/`: U.S.
government public-domain data from CISA
(https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json; site
policies at https://www.cisa.gov/about/site-policies). It is pinned by SHA-256 in
`src/repo_audit/vendor/kev/PROVENANCE` and refreshed only by `repo-audit scan --refresh-kev`.

## 2. Fetched at runtime, not redistributed

**splinter.sql** (https://github.com/supabase/splinter). supabase/splinter publishes no license,
so repo-audit does not ship it. The Supabase RLS lane downloads it on first use from commit
`a7f71080ed059de8a7f00addd71ade19b82a4108`, verifies it against SHA-256
`618a189a2d25c81e1d77efb24acca72c9c832aeac9680ba06a1ba5ec666b2d3d`, and caches it under the user
cache dir (`$XDG_CACHE_HOME/repo-audit/splinter/` or `~/.cache/repo-audit/splinter/`). If it
cannot be fetched and verified, the static RLS floor reports `unavailable`.

Other items fetched at runtime:

| Item | When | Provider | License or terms |
|---|---|---|---|
| OSV vulnerability data | first scan; `--refresh-vuln-db` | https://osv.dev | see the provider's terms |
| grype vulnerability database | first scan; `--refresh-vuln-db` | https://github.com/anchore/grype-db | see the provider's terms |
| Semgrep rule packs | default SAST pass (`--no-sast` turns it off) | https://github.com/semgrep/semgrep-rules | Semgrep Rules License v1.0 (https://semgrep.dev/legal/rules-license) |
| EPSS scores | `--epss` only | https://www.first.org/epss | see the provider's terms |
| CISA KEV feed | `--refresh-kev` only | https://www.cisa.gov | U.S. public domain |
| `supabase/postgres` Docker image | Supabase RLS lane | https://github.com/supabase/postgres | PostgreSQL License (repository) |
| `zaproxy/zap-stable` Docker image | DAST, when a target opts in | https://github.com/zaproxy/zaproxy | Apache-2.0 |

## 3. Python dependencies (installed from PyPI by the user; not redistributed)

| Package | License |
|---|---|
| typer | MIT |
| rich | MIT |
| pydantic | MIT |
| jinja2 | BSD-3-Clause |
| pygit2 | GPLv2 with linking exception |
| ruamel.yaml | MIT |
| claude-agent-sdk | MIT |
| defusedxml | PSF License |
| testcontainers | Apache-2.0 |
| psycopg | LGPL-3.0-only |
| pgrls | MIT |
| squawk-cli | Apache-2.0 OR MIT |

`pglast` (GPL-3.0-or-later) is installed transitively through `pgrls`, and `psycopg` is
LGPL-3.0. repo-audit does not bundle or redistribute either.

## 4. Tools invoked on PATH (not distributed)

| Tool | Upstream | License |
|---|---|---|
| semgrep | https://github.com/semgrep/semgrep | LGPL-2.1 |
| gitleaks | https://github.com/gitleaks/gitleaks | MIT |
| mobsfscan | https://github.com/MobSF/mobsfscan | LGPL-3.0 |
| detekt | https://github.com/detekt/detekt | Apache-2.0 |
| checkov | https://github.com/bridgecrewio/checkov | Apache-2.0 |
| hadolint | https://github.com/hadolint/hadolint | GPL-3.0 |
| zizmor | https://github.com/zizmorcore/zizmor | MIT |
| actionlint | https://github.com/rhysd/actionlint | MIT |
| jscpd | https://github.com/kucherenko/jscpd | MIT |
| ZAP | https://github.com/zaproxy/zaproxy | Apache-2.0 |
| tsc (TypeScript) | https://github.com/microsoft/TypeScript | Apache-2.0 |
| eslint | https://github.com/eslint/eslint | MIT |
| knip | https://github.com/webpro-nl/knip | ISC |
| ruff | https://github.com/astral-sh/ruff | MIT |
| mypy | https://github.com/python/mypy | MIT |
| gradle | https://github.com/gradle/gradle | Apache-2.0 |

repo-audit runs these as separate processes when it finds them and ships none of them.

**CodeQL.** The CodeQL CLI (https://github.com/github/codeql-cli-binaries) is under the GitHub
CodeQL Terms and Conditions, not an open-source license. Those terms permit academic research,
demonstrating the software, and analysis of codebases released under an OSI-approved license.
Scanning private or commercial code requires a paid GitHub Advanced Security license. repo-audit
leaves CodeQL off unless the target's `.repo-audit.yaml` enables it: its `codeql:` block must set
`enabled: true` and `use_rights_attestation: true` and name a `use_rights` ground.
