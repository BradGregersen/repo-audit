# SCA Fixture Provenance (D-06-13 freeze)

Frozen REAL output from the vendored osv-scanner 2.3.8 + Grype 0.112.0 binaries,
recorded BEFORE any enrichment (Plan 03) or corroboration (Plan 04) logic is
written (VALIDATION.md / D-06-13). Plans 03/04 build against the CONFIRMED field
paths below — not against guesses. This mirrors the Phase-6 SARIF recorded-fixture
discipline (`tests/adapters/sarif/fixtures/PROVENANCE.md`).

The osv-scanner **SARIF** shape is already frozen at
`tests/adapters/sarif/fixtures/osv-scanner/sample.sarif` (Phase 6) and is NOT
duplicated here. This directory records the NEW shapes Plans 03/04 need: osv
**native JSON**, grype **SARIF**, grype **JSON**, and `grype db status` text.

**Capture date:** 2026-06-02 (all entries).
**Host:** linux-x86_64.
**Throwaway project:** a single-line `requirements.txt` pinning `urllib3==1.23.0`
(a known-vulnerable PyPI release; continuity with the existing osv SARIF fixture's
urllib3 subject). Author-controlled, no secrets — threat T-07-04 (accept).

## Tool versions

| Tool | Version | Binary |
|------|---------|--------|
| osv-scanner | 2.3.8 (osv-scalibr 0.4.5) | `src/repo_audit/vendor/osv-scanner/osv-scanner` |
| grype | 0.112.0 | `src/repo_audit/vendor/grype/grype` |

## Exact recording argv

osv native JSON (`osv-scanner/sample.json`):
```
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/tmp/osvdb \
  osv-scanner scan source \
  --offline-vulnerabilities --download-offline-databases \
  --all-packages \
  --format json --lockfile=requirements.txt
```
(exit code **1** = vulnerabilities found, osv's normal "vulns detected" signal,
NOT a failure. `scan source` is the v2.3.8 subcommand confirmed via
`scan source --help`. `--all-packages` requested to surface package-level data;
see the `dependency_groups` note below. A7 resolved: the v2 subcommand is
`scan source --lockfile=...`, not the legacy bare `osv-scanner --lockfile`.)

grype DB seed (one-time, network):
```
GRYPE_DB_CACHE_DIR=/tmp/grypedb grype db update
```

grype SARIF (`grype/sample.sarif`):
```
GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_CACHE_DIR=/tmp/grypedb grype dir:<tmp> -o sarif
```

grype JSON (`grype/sample.json`):
```
GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_CACHE_DIR=/tmp/grypedb grype dir:<tmp> -o json
```

grype DB status (`grype/db-status.txt`):
```
GRYPE_DB_CACHE_DIR=/tmp/grypedb grype db status
```

The temp scan path was rewritten by grype to `/requirements.txt` in the SARIF
`artifactLocation.uri` (grype's `dir:` normalisation); no manual sanitisation was
applied — the fixtures are byte-faithful to the tools' emission.

## Confirmed field paths (the contract Plans 03/04 read)

### osv native JSON — `osv-scanner/sample.json` (resolves A4)

- **Vulnerable package:** `results[].packages[].package.{name,version,ecosystem}`
  → e.g. `urllib3` / `1.23.0` / `PyPI`.
- **`dependency_groups`: ABSENT (value is `null`) for a flat `requirements.txt`.**
  osv-scanner only populates `packages[].dependency_groups` (e.g. `["dev"]` /
  `["default"]`) when the lockfile ENCODES dependency groups — poetry.lock,
  Pipfile.lock, package-lock.json, etc. A plain `requirements.txt` carries no
  group metadata, so the field is `null` here. **Plan 03 MUST treat
  `dependency_groups` as Optional and default to "unknown"/None when absent — it
  cannot assume direct-vs-dev is always available** (A4 confirmed: present only
  for group-aware lockfiles). `--all-packages` does NOT synthesise groups.
- **Fix version:** lives at
  `results[].packages[].vulnerabilities[].affected[].ranges[].events[]` as a
  `{"fixed": "<version>"}` event inside a `type: "ECOSYSTEM"` range (paired with
  an `{"introduced": "0"}` event). There is **NO `FixedVersions` field** — the fix
  is the `fixed` event. e.g. PYSEC-2019-132 → `fixed: "1.24.3"`.
- **Severity score:** `results[].packages[].groups[].max_severity` (string, e.g.
  `"6.1"`, `"8.7"`). `groups[]` clusters aliased IDs:
  `groups[].ids` + `groups[].aliases` (the latter holds the CVE alias).
- **IDs / aliases:** `vulnerabilities[].id` is the native advisory ID
  (e.g. `PYSEC-2019-132`); `vulnerabilities[].aliases` holds the CVE + GHSA
  (e.g. `["CVE-2019-11236", "GHSA-r64q-w8jr-g9qp"]`).
- This fixture has 1 result → 1 package (urllib3) → 14 vulnerabilities clustered
  into 11 `groups`.

### grype JSON — `grype/sample.json` (resolves A5)

- **Vuln ID:** `matches[].vulnerability.id` (e.g. `GHSA-mh33-7rrq-662w` — grype's
  PRIMARY id is the GHSA, NOT the CVE).
- **Severity:** `matches[].vulnerability.severity` is a STRING band
  (`"High"`, `"Medium"`, `"Low"`, `"Critical"`, `"Negligible"`, `"Unknown"`) —
  NOT a numeric score. (Numeric CVSS is under `matches[].vulnerability.cvss[]`.)
- **Fix:** `matches[].vulnerability.fix.versions` (list, e.g. `["1.24.2"]`),
  `matches[].vulnerability.fix.state` (e.g. `"fixed"`, `"not-fixed"`,
  `"wont-fix"`, `"unknown"`). `fix.available[]` adds dated availability records.
- **Artifact:** `matches[].artifact.{name,version,purl,type,language}`
  → `urllib3` / `1.23.0` / `pkg:pypi/urllib3@1.23.0`.
- **CVE alias:** `matches[].relatedVulnerabilities[].id` holds the CVE
  (e.g. `CVE-2019-11324`) when the primary id is a GHSA. THIS is where corroboration
  joins osv (CVE) ↔ grype (GHSA): cross-reference via the related-vuln CVE.
- **DB snapshot in JSON:** `descriptor.db.status.{built,schemaVersion,from}` —
  `built` = `"2026-06-01T08:11:23Z"` (same value as `db status` text). This is a
  second, machine-readable source for `FeedProvenance.db_snapshot_date`.
- This fixture has 11 `matches` for urllib3.

### grype SARIF — `grype/sample.sarif` (resolves Pitfall 2)

- **`ruleId` is the COMPOSITE `{vulnID}-{pkgName}`** — first result's ruleId is
  `GHSA-mh33-7rrq-662w-urllib3` (verified). The same composite is the matching
  `tool.driver.rules[].id`. **A naive ruleId-as-CVE extractor is WRONG for grype.**
- The **bare vuln ID + package** are recoverable from:
  - `result.message.text` — prose, e.g.
    `"A high vulnerability in python package: urllib3, version 1.23.0 was found at: /requirements.txt"`,
  - `tool.driver.rules[].properties.purls` — the affected purl(s),
  - `tool.driver.rules[].properties.security-severity` — numeric band (e.g. `"8.7"`).
- `result.level` IS present (`"error"`) — unlike semgrep's SARIF.
- `physicalLocation.artifactLocation.uri = "/requirements.txt"` with a
  `region.startLine = 1` placeholder (grype points at the lockfile, line 1; it is
  not a source-line finding — corroboration must treat the line as nominal).
- The Pitfall-2 extractor for grype SARIF should derive the canonical
  `{cve/ghsa, package}` from `message.text` / `rules[].properties`, NOT by parsing
  the composite ruleId.

### advisory_count (resolves A3 / Open Question 3)

`grype db status` reports `Path / Schema / Built / From / Status` — it does **NOT**
report a vulnerability RECORD COUNT. The grype JSON `descriptor.db.providers`
block lists per-provider `captured`/`input` digests but no clean total count
either. **Decision: `FeedProvenance.advisory_count` ships `None` for grype**
(deterministic-numbers rule — we never invent a count we cannot cleanly read).
`FeedProvenance.db_snapshot_date` IS cleanly available: the `Built:` timestamp
(`2026-06-01T08:11:23Z`) from `db status` text or `descriptor.db.status.built` in JSON.

## Contract these fixtures freeze (binding, for Plans 03/04)

1. osv `dependency_groups` is Optional — absent for `requirements.txt`; default to
   None/"unknown", do not assume direct/dev classification (A4).
2. osv fix version = the `fixed` ECOSYSTEM-range event, not a `FixedVersions` field.
3. grype severity is a STRING band, not numeric; grype primary id is GHSA; the CVE
   is in `relatedVulnerabilities[].id` (A5) — that CVE is the osv↔grype join key.
4. grype SARIF ruleId is composite `{vulnID}-{pkg}`; canonical id/package come from
   `message.text` / `rules[].properties` (Pitfall 2).
5. `advisory_count` → None for grype; `db_snapshot_date` → grype `Built:` timestamp.

## Reproducing

Re-run the argv above against the vendored 2.3.8 / 0.112.0 binaries (seed the DBs
once with network), then re-freeze. Per D-06-13 the fixtures are committed
artifacts (not runtime code); a documented one-shot capture is the reproducible
record. If a future tool-version bump changes any field path above, update this
file's versions + the affected contract line in the SAME commit as the re-record.
