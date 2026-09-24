// Placeholder manifest. It exists only so the first-run vulnerability-database
// download knows to fetch the Go database. The module does not exist. There is
// deliberately no `go` directive, so no Go toolchain version is declared.
module example.invalid/repo-audit-seed

require example.invalid/repo-audit-seed-placeholder v0.0.0
