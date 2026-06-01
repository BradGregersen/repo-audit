# SARIF Fixture Provenance (D-06-13)

Frozen SARIF 2.1.0 corpus for the FND-01 / SC-1 eight-tool round-trip
(`tests/adapters/sarif/test_eight_tool_round_trip.py`). This mirrors the Phase 3
recorded-fixture discipline (the 33 frozen TypeScript triples): one representative,
**frozen** SARIF document per tool so the parser is proven against the real SARIF
shapes the tools emit — catching per-tool deviations from the SARIF 2.1.0 spec that
hand-authored stubs would miss.

All 8 documents round-trip through the **same** `sarif_to_findings` function; the
only per-tool difference is `default_dimension` + `severity_map` (see
`tests/adapters/sarif/conftest.py::TOOL_CONFIG`).

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
| dependency-cruiser | **docs-sourced** | 16.3.10 (target) | 2 | **NOT real-recorded.** dependency-cruiser's bundled SARIF reporter is not exposed by the installed CLI in this environment (`--output-type sarif` → "not a valid output type" across the versions tried; the SARIF reporter is not bundled in the CLI build available here). This document reproduces dependency-cruiser's documented SARIF reporter shape (a `no-circular` rule violation at `level=error` + a `no-orphans` warning, each with `ruleId`, `level`, `message`, and `physicalLocation` carrying `artifactLocation.uri` + `region.startLine`), consistent with the reporter and rules reference at <https://github.com/sverweij/dependency-cruiser> (`doc/rules-reference.md`, SARIF reporter). When dependency-cruiser lands as a real adapter (Phase 14, architecture-fitness), re-record this fixture from live `depcruise` output and flip this row to real-recorded. |

## Contract these fixtures assert (binding, from Plan 06-01)

A tool-reported `critical`/`blocker` does **NOT** surface as a `critical` Finding.
It surfaces as **`severity="major"` + `confidence="candidate"` + a non-empty
`confidence_caveat`**, with the faithful severity preserved in
`evidence.parsed_value["faithful_severity"]`. There are **no** `candidate`+`critical`
Findings anywhere. Fixtures whose real output drives a faithful `critical`
(osv-scanner via 8.9 band is `major`; semgrep 9.8, checkov/mobsfscan `error`,
dependency-cruiser `no-circular` `error` → faithful `critical` → capped) exercise
this cap + caveat path against real tool output.

## Reproducing

The captures above were produced one-shot in a scratch workdir. To re-record a
real fixture, run the listed command, then trim to the first 1–2 results, prune
`driver.rules[]` to the referenced rules, rewrite absolute paths to relative, and
update this file's version + date. Per D-06-13 / D-06-02 the fixtures are committed
artifacts (not runtime code), so a documented one-shot capture is the frozen,
reproducible record.
