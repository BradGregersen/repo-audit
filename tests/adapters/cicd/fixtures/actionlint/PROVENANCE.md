# actionlint fixture provenance

**File:** `sample.json`
**Tool:** `actionlint` (target `v1.7.12`, GitHub releases 2026-03-30)
**Command (intended):** `actionlint -format '{{json .}}' -no-color`
**Origin:** **DOCS-SOURCED (hand-authored)** — `actionlint` was NOT on PATH in the
Wave-0 execution environment, so the fixture was hand-authored from actionlint's
documented JSON shape (`docs/usage.md`: error fields `Message / Filepath / Line /
Column / EndColumn / Kind / Snippet`, serialized via the Go struct's JSON tags).
**Re-record when** an actionlint binary is available: run the command above
against a small workflow with deliberate problems and replace `sample.json`
verbatim, then update this note to ORIGIN: LIVE-RECORDED with the binary version.

## Assumption A1 — PINNED KEY CASING (BINDING CONTRACT for Plan 02's actionlint map)

The `actionlint -format '{{json .}}'` serialization emits a **JSON ARRAY** of error
objects keyed by the **lowercase** Go-struct JSON tags. The pinned keys, exactly as
the Wave-1 `_actionlint_json_to_findings` map MUST read them:

| JSON key   | Type           | Maps to                                  |
|------------|----------------|------------------------------------------|
| `message`  | string         | `Evidence.output_snippet` + `Finding`-level message text |
| `filepath` | string         | `Finding.file` (relative to repo root, e.g. `.github/workflows/ci.yml`) |
| `line`     | int            | `Finding.line` + `Evidence.line_range=(line, line)` |
| `column`   | int            | `Evidence.parsed_value["column"]`        |
| `kind`     | string         | `Finding.rule_id` (e.g. `shellcheck`, `action`, `expression`) — the actionlint rule family |
| `snippet`  | string         | `Evidence.parsed_value["snippet"]` (source excerpt with caret underline) |

Notes pinned by this fixture:

- Keys are **lowercase** (not `Message`/`Filepath`/...). The Go template variable
  names are TitleCase, but `{{json .}}` serializes via the struct's JSON tags, which
  are lowercase. **The map reads lowercase keys.**
- `EndColumn` exists as a Go struct field but is **NOT present** in the `{{json .}}`
  serialization (no `end_column` key). The map MUST NOT depend on it.
- `kind` is the actionlint rule FAMILY (`shellcheck`, `action`, `expression`,
  `syntax-check`, `runner-label`, `events`, `permissions`, ...), used as `rule_id`.
- All actionlint findings are lint-level: `severity="minor"`, `evidence_type="static"`,
  `confidence="candidate"`, `dimension="process"` (per adapter.yaml / D-13-02). The
  SCH-04 candidate cap is a no-op at `minor`.

The fixture contains **3 entries of distinct `kind`** (`shellcheck`, `action`,
`expression`) so the Wave-1 parse test can assert the map handles multiple rule
families and pins the key contract above.
