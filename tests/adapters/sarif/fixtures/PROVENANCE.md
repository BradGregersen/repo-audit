# SARIF Fixture Provenance (D-06-13)

Frozen SARIF 2.1.0 corpus for the FND-01 / SC-1 seven-tool round-trip
(`tests/adapters/sarif/test_eight_tool_round_trip.py`). This mirrors the Phase 3
recorded-fixture discipline (the 33 frozen TypeScript triples): one representative,
**frozen** SARIF document per tool so the parser is proven against the real SARIF
shapes the tools emit — catching per-tool deviations from the SARIF 2.1.0 spec that
hand-authored stubs would miss.

All 7 documents round-trip through the **same** `sarif_to_findings` function; the
only per-tool difference is `default_dimension` + `severity_map` (see
`tests/adapters/sarif/conftest.py::TOOL_CONFIG`).

> **Phase 14 update (2026-06-04):** dependency-cruiser (formerly the 8th row) was
> **retired** from this SARIF harness. It ships **no SARIF reporter** in any
> version (`--output-type sarif` errors; no `src/report/sarif.mjs` — verified
> against 17.4.3), so its old docs-sourced `dependency-cruiser/sample.sarif`
> exercised a code path the tool cannot emit. The architecture adapter consumes
> dependency-cruiser's **JSON reporter** instead; the REAL JSON fixture now lives
> at `tests/adapters/architecture/fixtures/dependency-cruiser/sample.json`. The
> superseded `fixtures/dependency-cruiser/sample.sarif` is no longer referenced
> by any test.

**Capture date:** 2026-06-01 (all entries).

**Sanitisation:** absolute capture paths (the temp workdir) were rewritten to
stable relative paths (e.g. `vuln.py`, `tf/main.tf`). No other content was edited.
Large real outputs were **trimmed to the first 1–2 results** and the driver
`rules[]` pruned to only the rules those kept results reference — the kept results
themselves are byte-faithful to the tool's emission.

## Per-tool record

| Tool | Provenance | Tool version | Results kept | Notes |
|------|------------|--------------|--------------|-------|
| osv-scanner | **real-recorded** | 2.3.8 (osv-scalibr 0.4.5) | 1 of 37 | `scan --lockfile=requirements.txt --format sarif` on a `requests==2.19.0` / `jinja2==2.10` lockfile. Carries `rule.properties.security-severity` (`"8.9"`). **Real per-tool deviation:** osv-scanner locates the *lockfile*, not a source line — its `physicalLocation` has `artifactLocation.uri` but **no `region.startLine`** (a dependency scanner has no line). The parser yields `line=None`, which is correct and exactly the kind of real-shape divergence this corpus exists to pin. |
| semgrep | **real-recorded** | 1.163.0 | 1 of 1 | `semgrep --config <1-rule.yaml> --sarif` on a `subprocess.run(..., shell=True)` Python file. Carries `rule.properties.security-severity` (`"9.8"`). **Real per-tool deviation:** the *result* has **no `level`** field — semgrep encodes the level only in `rule.defaultConfiguration.level`. Severity is therefore driven entirely by the security-severity numeric band (9.8 → faithful `critical`, capped to `major` at `candidate`). |
| mobsfscan | **real-recorded** | 0.4.5 | 2 of 7 | `mobsfscan --sarif` on a Java file using `DES/ECB` (`weak_cipher`, `level=error`). |
| detekt | **real-recorded** | 1.23.8 | 2 of 3 | `detekt-cli --report sarif` (CLI all-jar) on a trivial `.kt` (`MagicNumber`, `level=warning`). Driver `rules[]` pruned from 214 to the 2 referenced. |
| zizmor | **real-recorded** | 1.25.2 | 2 of 5 | `zizmor --format sarif` on a `pull_request_target` workflow with an untrusted-checkout + script-injection pattern (`artipacked`, `level=warning`). |
| hadolint | **real-recorded** | 2.14.0 | 2 of 3 | `hadolint -f sarif -` on a 3-line Dockerfile (`DL3006`, `level=warning`). Run via the official `hadolint/hadolint` Docker image; stdin Dockerfile → `artifactLocation.uri == "-"` (real hadolint behaviour for stdin input). |
| checkov | **real-recorded** | 3.2.531 | 2 of 14 | `checkov -d tf -o sarif` on a public-read S3 bucket + open security group (`level=error`). No `security-severity` on checkov's rules (relies on level). |
| dependency-cruiser | **RETIRED — no SARIF reporter** (Phase 14) | 17.4.3 (verified) | — | **No longer part of this harness.** dependency-cruiser ships **no SARIF reporter** in any version: `--output-type sarif` errors ("not a valid output type") and there is **no `src/report/sarif.mjs`** in the package (verified against 17.4.3, 2026-06-04). The Phase-6 docs-sourced `dependency-cruiser/sample.sarif` therefore tested a code path the tool cannot emit (false confidence) and was removed from `conftest.py::TOOL_CONFIG`. The architecture adapter (Phase 14, ARCH-01) uses dependency-cruiser's **JSON reporter** (`--output-type json`); a **REAL-recorded** JSON fixture lives at `tests/adapters/architecture/fixtures/dependency-cruiser/sample.json` (depcruise@17.4.3, a real `no-circular` cycle violation). The superseded `fixtures/dependency-cruiser/sample.sarif` is retained on disk only as a record and is referenced by no test. |

## Contract these fixtures assert (binding, from Plan 06-01)

A tool-reported `critical`/`blocker` does **NOT** surface as a `critical` Finding.
It surfaces as **`severity="major"` + `confidence="candidate"` + a non-empty
`confidence_caveat`**, with the faithful severity preserved in
`evidence.parsed_value["faithful_severity"]`. There are **no** `candidate`+`critical`
Findings anywhere. Fixtures whose real output drives a faithful `critical`
(semgrep 9.8 via the security-severity band; checkov/mobsfscan `error`) exercise
this cap + caveat path against real tool output. (The retired dependency-cruiser
`no-circular`-error path no longer participates — it emitted no SARIF; the
architecture adapter's JSON severity map tops out at `major` for `error`, so it
never reaches the cap at all.)

## Reproducing

The captures above were produced one-shot in a scratch workdir. To re-record a
real fixture, run the listed command, then trim to the first 1–2 results, prune
`driver.rules[]` to the referenced rules, rewrite absolute paths to relative, and
update this file's version + date. Per D-06-13 / D-06-02 the fixtures are committed
artifacts (not runtime code), so a documented one-shot capture is the frozen,
reproducible record.
