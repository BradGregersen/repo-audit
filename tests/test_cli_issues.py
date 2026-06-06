"""Wave-0 scaffold for ``repo-audit issues`` (Phase 19, Plan 19-01).

This file lands BEFORE any implementation so that every Wave-1/2
implementation task can bind an ``<automated>`` command to a subset of it.
It carries three reusable module-scope helpers:

    * ``_make_repo`` / ``_make_repo_wrong_origin`` — pygit2-seeded repo dirs
      (one commit + an ``origin`` remote) mirroring ``tests/test_cli_fleet.py``.
      The wrong-origin variant drives the D-10 wrong-repo identity-guard test.
    * ``_write_sidecar`` — writes a schema-valid ``ScanReport`` sidecar seeding
      ONE confirmed+critical+static finding (with a SAFE-01 ``confidence_caveat``
      so construction does not raise), several confirmed+major findings across
      dimensions, and a ``candidate`` finding that eligibility must exclude.
    * ``fake_run_tool`` — a ``run_tool``-signature monkeypatch helper returning
      canned ``InvocationResult``s keyed on argv membership (remote / repo view /
      issue list / label create / issue create). Every ``create`` argv is tracked
      in ``CREATED_ISSUE_ARGV`` so propose-gate tests can assert zero creates
      fired on ``n``/EOF.

The ISS-01..ISS-04 test functions whose NAMES satisfy the 19-VALIDATION.md
``-k`` filters are each ``pytest.importorskip``-gated on the as-yet-unbuilt
module they exercise. They SKIP cleanly now and flip ACTIVE wave-by-wave as the
Wave-1/2 symbols land — the project's established SKIPPED→ACTIVE discipline
(Phase 03/04 importorskip pattern). The bodies carry the real assertions the
implementation must satisfy; they are NOT bare ``pass``.
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pygit2
import pytest
from typer.testing import CliRunner

from repo_audit.adapters.base import InvocationResult
from repo_audit.schema.finding import Evidence, Finding
from repo_audit.schema.report import ReportMeta, ScanReport

# Canonical owner/repo this scaffold's fixtures speak for. The identity guard
# (ISS-04) treats this as the only repo a self-file is allowed against.
_CANON_SLUG = "repo-audit"
_CANON_OWNER_REPO = "BradGregersen/repo-audit"
_CANON_ORIGIN = f"git@github.com:{_CANON_OWNER_REPO}.git"
_WRONG_ORIGIN = "git@github.com:SomeoneElse/other-repo.git"

# Every ``gh issue create`` argv the fake sees is appended here so propose-gate
# tests can assert all-or-nothing: zero creates on ``n``/EOF, all on ``y``.
CREATED_ISSUE_ARGV: list[list[str]] = []

# A known fingerprint hash embedded in the canned ``gh issue list`` open issue,
# used to drive the dedup-skip test (ISS-04).
_OPEN_ISSUE_FINGERPRINT = "abc123def456"

runner = CliRunner()


# --------------------------------------------------------------------------- #
# Helper 1: pygit2-seeded repos (mirrors tests/test_cli_fleet.py::_make_repo). #
# --------------------------------------------------------------------------- #
def _make_repo(tmp_path: Path, *, origin: str = _CANON_ORIGIN, name: str = "repo") -> Path:
    """Create an initialized git repo dir with one commit AND an origin remote.

    The origin remote lets origin-resolution + identity-guard tests run against
    a real remote URL. Defaults to the canonical repo-audit origin.
    """
    repo_path = tmp_path / name
    repo_path.mkdir(parents=True, exist_ok=True)
    repo = pygit2.init_repository(str(repo_path), bare=False)
    (repo_path / "README.md").write_text(f"# {name}\n", encoding="utf-8")
    repo.index.add("README.md")
    repo.index.write()
    sig = pygit2.Signature("Tester", "tester@example.com")
    tree = repo.index.write_tree()
    repo.create_commit("HEAD", sig, sig, "initial", tree, [])
    repo.remotes.create("origin", origin)
    return repo_path


def _make_repo_wrong_origin(tmp_path: Path) -> Path:
    """A repo whose origin points at a DIFFERENT owner/repo (D-10 guard test)."""
    return _make_repo(tmp_path, origin=_WRONG_ORIGIN, name="wrong-origin-repo")


# --------------------------------------------------------------------------- #
# Helper 2: schema-valid sidecar fixture (adapts test_cli_fleet::_write_sidecar)#
# --------------------------------------------------------------------------- #
def _make_finding(
    *,
    dimension: str,
    severity: str,
    confidence: str,
    evidence_type: str = "static",
    confidence_caveat: str | None = None,
    rule_id: str = "RULE",
    file: str | None = "src/example.py",
    line: int | None = 42,
) -> Finding:
    """Construct a single Finding through the real pydantic model (extra='forbid').

    Building findings via the real model means the scaffold cannot encode a shape
    the loader will later reject (T-19-01 tampering mitigation).
    """
    return Finding(
        dimension=dimension,
        severity=severity,
        confidence=confidence,
        evidence_type=evidence_type,
        evidence=Evidence(tool="repo", output_snippet="snippet"),
        confidence_caveat=confidence_caveat,
        rule_id=rule_id,
        file=file,
        line=line,
        source_tool="repo",
        recommendation="Fix it.",
    )


def _write_sidecar(repo: Path, scan_date: date | None = None) -> Path:
    """Write a ScanReport sidecar with an eligibility-spanning finding set.

    Seeds:
      (a) ONE confirmed + critical + static finding WITH a non-empty
          confidence_caveat (SAFE-01 — construction RAISES without it) in the
          ``security`` dimension → drafts as a SOLO issue.
      (b) THREE confirmed + major findings across ``quality`` / ``correctness``
          / ``architecture_rot`` → drafts into per-dimension rollups.
      (c) ONE candidate finding that eligibility MUST exclude (only confirmed
          findings are file-eligible).
    """
    if scan_date is None:
        scan_date = date.today()

    findings = [
        # (a) solo: critical + static REQUIRES a confidence_caveat (SAFE-01).
        _make_finding(
            dimension="security",
            severity="critical",
            confidence="confirmed",
            evidence_type="static",
            confidence_caveat="Static analysis only — runtime exploit not verified.",
            rule_id="SEC-CRIT-1",
            file="src/auth.py",
            line=10,
        ),
        # (b) three confirmed + major across dimensions → rollups.
        _make_finding(
            dimension="quality",
            severity="major",
            confidence="confirmed",
            rule_id="QUAL-MAJ-1",
            file="src/quality.py",
        ),
        _make_finding(
            dimension="correctness",
            severity="major",
            confidence="confirmed",
            rule_id="CORR-MAJ-1",
            file="src/correctness.py",
        ),
        _make_finding(
            dimension="architecture_rot",
            severity="major",
            confidence="confirmed",
            rule_id="ARCH-MAJ-1",
            file="src/arch.py",
        ),
        # (c) candidate — eligibility must EXCLUDE this one.
        _make_finding(
            dimension="quality",
            severity="minor",
            confidence="candidate",
            rule_id="QUAL-CAND-1",
            file="src/candidate.py",
        ),
    ]

    report = ScanReport(
        meta=ReportMeta(
            repo_slug=_CANON_SLUG,
            commit_sha="a" * 40,
            scan_date=scan_date,
            tool_version="0.1.0",
        ),
        findings=findings,
    )
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{_CANON_SLUG}-state-report-{scan_date}.json"
    json_path.write_text(report.model_dump_json(), encoding="utf-8")
    return json_path


# --------------------------------------------------------------------------- #
# Helper 3: fake_run_tool (mirrors tests/adapters/sca/test_osv.py).            #
# --------------------------------------------------------------------------- #
# Canned ``gh issue list --json`` payload: one OPEN issue whose body carries a
# known fingerprint marker, to drive the dedup-skip test (ISS-04).
_GH_ISSUE_LIST_JSON = (
    '[{"number": 7, "state": "OPEN", "title": "[arch] existing finding", '
    '"body": "Some description.\\n\\n<!-- arch-fingerprint: '
    + _OPEN_ISSUE_FINGERPRINT
    + ' -->\\n"}]'
)


def fake_run_tool(argv, *, env, cwd, timeout_seconds):
    """Return a canned ``InvocationResult`` keyed on argv membership.

    Mirrors the ``run_tool`` signature exactly so it can be monkeypatched onto
    the issues modules' ``run_tool`` symbol. Routing:

        "remote" in argv → stdout = the canonical origin URL
        "view"   in argv → stdout = ``BradGregersen/repo-audit\\n``
        "list"   in argv → stdout = canned ``gh issue list --json`` array
        "label"  in argv → rc=0 (label created / already exists)
        "create" in argv → stdout = a new issue URL, rc=0; argv tracked
    """
    argv = list(argv)
    if "remote" in argv:
        return InvocationResult(stdout=_CANON_ORIGIN + "\n", returncode=0, command=argv)
    if "view" in argv:
        return InvocationResult(stdout=_CANON_OWNER_REPO + "\n", returncode=0, command=argv)
    if "list" in argv:
        return InvocationResult(stdout=_GH_ISSUE_LIST_JSON, returncode=0, command=argv)
    if "label" in argv:
        return InvocationResult(stdout="", returncode=0, command=argv)
    if "create" in argv:
        CREATED_ISSUE_ARGV.append(argv)
        return InvocationResult(
            stdout=f"https://github.com/{_CANON_OWNER_REPO}/issues/1\n",
            returncode=0,
            command=argv,
        )
    # Unknown invocation — never raise (D-25 floor); empty success.
    return InvocationResult(stdout="", returncode=0, command=argv)


@pytest.fixture(autouse=True)
def _reset_created_issue_argv():
    """Each test starts with a clean create-tracker."""
    CREATED_ISSUE_ARGV.clear()
    yield
    CREATED_ISSUE_ARGV.clear()


# --------------------------------------------------------------------------- #
# Sanity: the fixture helpers themselves construct (no importorskip gate).     #
# These prove the SAFE-01-honoring sidecar + repos build before any Wave-1/2   #
# symbol exists, so the scaffold is usable from day one.                       #
# --------------------------------------------------------------------------- #
def test_scaffold_sidecar_constructs(tmp_path):
    """The SAFE-01-honoring sidecar fixture constructs without raising."""
    repo = _make_repo(tmp_path)
    json_path = _write_sidecar(repo)
    assert json_path.exists()
    report = ScanReport.model_validate_json(json_path.read_text(encoding="utf-8"))
    # The critical+static finding carries its mandatory caveat (SAFE-01 held).
    crit = [f for f in report.findings if f.severity == "critical"]
    assert len(crit) == 1
    assert crit[0].confidence_caveat
    # Confirmed-major spread + the excluded candidate are all present.
    majors = [f for f in report.findings if f.severity == "major"]
    assert len(majors) == 3
    assert any(f.confidence == "candidate" for f in report.findings)


def test_scaffold_repos_have_expected_origins(tmp_path):
    """Both repo variants carry the origins the guard tests rely on."""
    good = _make_repo(tmp_path / "g")
    wrong = _make_repo_wrong_origin(tmp_path / "w")
    good_repo = pygit2.Repository(str(good))
    wrong_repo = pygit2.Repository(str(wrong))
    assert good_repo.remotes["origin"].url == _CANON_ORIGIN
    assert wrong_repo.remotes["origin"].url == _WRONG_ORIGIN


# =========================================================================== #
# ISS-01 — drafting: solo (critical/blocker) + per-dimension rollup;          #
#           no sidecar → clear error; stale sidecar warns but proceeds.       #
# Gated on issues.draft / issues.loader landing.                              #
# =========================================================================== #
def test_draft_solo_and_rollup(tmp_path, monkeypatch):
    """Critical/blocker findings draft SOLO; major/minor/info group into
    per-dimension rollups. Only confirmed findings are eligible."""
    loader = pytest.importorskip("repo_audit.issues.loader")
    draft = pytest.importorskip("repo_audit.issues.draft")

    repo = _make_repo(tmp_path)
    _write_sidecar(repo)

    report = loader.load_latest_sidecar(repo)
    drafts = draft.build_drafts(report)

    # The one confirmed critical → exactly one solo draft.
    solos = [d for d in drafts if getattr(d, "kind", None) == "solo"]
    assert len(solos) == 1
    # Three confirmed-major dimensions → three rollup drafts (one per dimension).
    rollups = [d for d in drafts if getattr(d, "kind", None) == "rollup"]
    rollup_dims = {getattr(d, "dimension", None) for d in rollups}
    assert rollup_dims == {"quality", "correctness", "architecture_rot"}
    # The candidate finding is excluded from every draft.
    all_rule_ids = {
        rid
        for d in drafts
        for rid in getattr(d, "rule_ids", [])
    }
    assert "QUAL-CAND-1" not in all_rule_ids


def test_same_day_tie_picks_newest_written(tmp_path):
    """WR-02: when two sidecars share the same scan_date, the LATER-WRITTEN file
    wins deterministically (not whatever glob order yields first)."""
    import os
    import time

    loader = pytest.importorskip("repo_audit.issues.loader")

    repo = _make_repo(tmp_path)
    today = date.today()
    out_dir = repo / "docs" / "state-reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    older = out_dir / f"{_CANON_SLUG}-state-report-{today}-1.json"
    newer = out_dir / f"{_CANON_SLUG}-state-report-{today}-2.json"

    report = ScanReport(
        meta=ReportMeta(
            repo_slug=_CANON_SLUG, commit_sha="a" * 40,
            scan_date=today, tool_version="0.1.0",
        ),
        findings=[
            _make_finding(
                dimension="security", severity="critical", confidence="confirmed",
                evidence_type="static",
                confidence_caveat="Static only.", rule_id="SEC-1", file="src/auth.py",
            )
        ],
    )
    payload = report.model_dump_json()
    older.write_text(payload, encoding="utf-8")
    newer.write_text(payload, encoding="utf-8")

    # Force a deterministic mtime ordering: older file older, newer file newest.
    now = time.time()
    os.utime(older, (now - 100, now - 100))
    os.utime(newer, (now, now))

    assert loader.find_latest_sidecar(repo) == newer


def test_no_sidecar_errors_clearly(tmp_path):
    """No sidecar present → a clear, actionable error (not a stack trace)."""
    loader = pytest.importorskip("repo_audit.issues.loader")

    repo = _make_repo(tmp_path)  # no _write_sidecar call
    with pytest.raises(loader.NoSidecarError) as exc:
        loader.load_latest_sidecar(repo)
    msg = str(exc.value).lower()
    assert "repo-audit scan" in msg or "no state report" in msg or "sidecar" in msg


def test_stale_sidecar_warns_but_proceeds(tmp_path, recwarn):
    """A sidecar older than the staleness window WARNS but still loads."""
    loader = pytest.importorskip("repo_audit.issues.loader")

    repo = _make_repo(tmp_path)
    old_date = date.today() - timedelta(days=120)
    _write_sidecar(repo, scan_date=old_date)

    report = loader.load_latest_sidecar(repo)
    # It still proceeds: the report loaded with its findings intact.
    assert report.findings
    # And it warned about staleness (warning surfaced, not raised).
    assert any("stale" in str(w.message).lower() for w in recwarn.list)


# =========================================================================== #
# ISS-02 — propose gate: dry-run shown; n/EOF files nothing; y files all      #
#           (all-or-nothing). Gated on the ``issues`` CLI command existing.   #
# =========================================================================== #
def _issues_is_registered_command() -> bool:
    """True only once ``issues`` is a registered Typer command on the app."""
    try:
        from repo_audit import cli as cli_mod
    except Exception:
        return False
    app = getattr(cli_mod, "app", None)
    if app is None:
        return False
    names = {getattr(c, "name", None) for c in getattr(app, "registered_commands", [])}
    # Typer also stores callback function names; check both.
    names |= {
        getattr(c, "callback", None).__name__
        for c in getattr(app, "registered_commands", [])
        if getattr(c, "callback", None) is not None
    }
    return "issues" in names


pytestmark_iss02 = pytest.mark.skipif(
    not _issues_is_registered_command(),
    reason="issues CLI command not yet registered (Wave-2 lands it)",
)


@pytestmark_iss02
def test_propose_gate_n_files_nothing(tmp_path, monkeypatch):
    """Declining the propose gate (``n``) files NOTHING — zero gh issue create."""
    pytest.importorskip("repo_audit.issues")
    from repo_audit import cli as cli_mod
    import repo_audit.issues.filer as filer_mod
    import repo_audit.issues.targeting as targeting_mod
    import repo_audit.issues.dedup as dedup_mod

    repo = _make_repo(tmp_path)
    _write_sidecar(repo)
    # WR-01: patch ALL THREE run_tool seams (targeting/dedup/filer) so the test
    # is hermetic — nothing shells out to git/gh against the live repo.
    monkeypatch.setattr(filer_mod, "run_tool", fake_run_tool)
    monkeypatch.setattr(targeting_mod, "run_tool", fake_run_tool)
    monkeypatch.setattr(dedup_mod, "run_tool", fake_run_tool)

    result = runner.invoke(cli_mod.app, ["issues", str(repo)], input="n\n")
    assert result.exit_code == 0, result.output
    # Dry-run was shown, but no create fired (all-or-nothing).
    assert CREATED_ISSUE_ARGV == []


@pytestmark_iss02
def test_propose_gate_y_files_all(tmp_path, monkeypatch):
    """Approving the propose gate (``y``) files ALL eligible drafts."""
    pytest.importorskip("repo_audit.issues")
    from repo_audit import cli as cli_mod
    import repo_audit.issues.filer as filer_mod
    import repo_audit.issues.targeting as targeting_mod
    import repo_audit.issues.dedup as dedup_mod

    repo = _make_repo(tmp_path)
    _write_sidecar(repo)
    # WR-01: patch ALL THREE run_tool seams (targeting/dedup/filer) so the test
    # is hermetic — nothing shells out to git/gh against the live repo.
    monkeypatch.setattr(filer_mod, "run_tool", fake_run_tool)
    monkeypatch.setattr(targeting_mod, "run_tool", fake_run_tool)
    monkeypatch.setattr(dedup_mod, "run_tool", fake_run_tool)

    result = runner.invoke(cli_mod.app, ["issues", str(repo)], input="y\n")
    assert result.exit_code == 0, result.output
    # All-or-nothing: at least the solo + the three rollups were created.
    assert len(CREATED_ISSUE_ARGV) >= 4


# =========================================================================== #
# ISS-03 — secret-lint blocks ONE draft, files the rest (never aborts the     #
#           whole run); labels created idempotently.                          #
# Gated on issues.filer / issues.draft.                                       #
# =========================================================================== #
def test_secret_lint_block_one_files_rest(tmp_path, monkeypatch):
    """A draft whose body trips secret-lint is dropped; the others still file.
    The whole run NEVER aborts on one tainted draft."""
    filer = pytest.importorskip("repo_audit.issues.filer")
    draft = pytest.importorskip("repo_audit.issues.draft")

    repo = _make_repo(tmp_path)
    _write_sidecar(repo)
    monkeypatch.setattr(filer, "run_tool", fake_run_tool)

    drafts = draft.build_drafts(loader_report(repo))
    # Inject a secret into ONE draft body so secret-lint must block it.
    drafts[0].body = drafts[0].body + "\nAKIAIOSFODNN7EXAMPLE\n"

    outcome = filer.file_all(repo, drafts, owner_repo=_CANON_OWNER_REPO)
    # The tainted draft was blocked; the remainder were filed.
    assert outcome.blocked_count == 1
    assert outcome.filed_count == len(drafts) - 1
    # The run did not abort — created issues fired for the clean drafts.
    assert len(CREATED_ISSUE_ARGV) == len(drafts) - 1


def test_rc0_empty_stdout_counts_as_filed_url_unknown(tmp_path, monkeypatch):
    """WR-05: gh issue create returning rc=0 with EMPTY stdout is recorded as
    'filed, URL unknown' (counted in filed_count), not as a create failure."""
    filer = pytest.importorskip("repo_audit.issues.filer")
    draft = pytest.importorskip("repo_audit.issues.draft")

    repo = _make_repo(tmp_path)
    _write_sidecar(repo)

    def no_url_run_tool(argv, *, env, cwd, timeout_seconds):
        argv = list(argv)
        if "create" in argv:
            CREATED_ISSUE_ARGV.append(argv)
            # rc=0 but NO url on stdout (the WR-05 case).
            return InvocationResult(stdout="", returncode=0, command=argv)
        return fake_run_tool(argv, env=env, cwd=cwd, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(filer, "run_tool", no_url_run_tool)

    drafts = draft.build_drafts(loader_report(repo))
    outcome = filer.file_all(repo, drafts, owner_repo=_CANON_OWNER_REPO)

    # Every clean draft is counted as filed (placeholder URL), none as a failure.
    assert outcome.filed_count == len(drafts)
    # A disclosure note was emitted for each URL-unknown create.
    assert any("no URL captured" in n for n in outcome.errors)
    # And none were mis-recorded as "failed to file".
    assert not any(n.startswith("failed to file") for n in outcome.errors)


def test_label_created_idempotently(tmp_path, monkeypatch):
    """``gh label create`` is idempotent: a re-run does not error on an
    already-existing label (rc=0 path), and the same label is not created twice
    within a single run."""
    filer = pytest.importorskip("repo_audit.issues.filer")
    draft = pytest.importorskip("repo_audit.issues.draft")

    repo = _make_repo(tmp_path)
    _write_sidecar(repo)

    label_calls: list[list[str]] = []

    def tracking_run_tool(argv, *, env, cwd, timeout_seconds):
        argv = list(argv)
        if "label" in argv:
            label_calls.append(argv)
        return fake_run_tool(argv, env=env, cwd=cwd, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(filer, "run_tool", tracking_run_tool)

    drafts = draft.build_drafts(loader_report(repo))
    filer.file_all(repo, drafts, owner_repo=_CANON_OWNER_REPO)

    # The repo-audit label is ensured at most once (idempotent), and every label call
    # tolerated the "already exists" rc=0 path without aborting.
    arch_label_calls = [c for c in label_calls if any("arch" in tok for tok in c)]
    assert len(arch_label_calls) <= 1


# =========================================================================== #
# ISS-04 — fingerprint excludes line; open-marker dedup; origin 4-form parse; #
#           identity guard blocks wrong-repo; self-file allowed when matched. #
# Gated on issues.fingerprint / issues.dedup / issues.targeting.              #
# =========================================================================== #
def test_fingerprint_excludes_line(tmp_path):
    """The fingerprint is stable across line-number drift: two findings that
    differ ONLY in ``line`` hash identically (the line is excluded)."""
    fingerprint = pytest.importorskip("repo_audit.issues.fingerprint")

    a = _make_finding(
        dimension="security", severity="major", confidence="confirmed",
        rule_id="SEC-1", file="src/auth.py", line=10,
    )
    b = _make_finding(
        dimension="security", severity="major", confidence="confirmed",
        rule_id="SEC-1", file="src/auth.py", line=99,
    )
    assert fingerprint.fingerprint(a) == fingerprint.fingerprint(b)


def test_empty_rule_recommendation_no_collision(tmp_path):
    """WR-03: two distinct findings in the same file with EMPTY rule_id and
    recommendation must not fingerprint identically (a folded discriminator
    keeps them distinct)."""
    fingerprint = pytest.importorskip("repo_audit.issues.fingerprint")

    a = Finding(
        dimension="security", severity="major", confidence="confirmed",
        evidence_type="static",
        evidence=Evidence(tool="repo", output_snippet="finding A snippet"),
        rule_id="", recommendation="", source_tool="repo",
        file="src/same.py", line=1,
    )
    b = Finding(
        dimension="security", severity="major", confidence="confirmed",
        evidence_type="static",
        evidence=Evidence(tool="repo", output_snippet="finding B snippet"),
        rule_id="", recommendation="", source_tool="repo",
        file="src/same.py", line=2,
    )
    assert fingerprint.build_fingerprint(a) != fingerprint.build_fingerprint(b)


def test_solo_title_guards_empty_rule_id(tmp_path):
    """WR-03: a solo draft for a finding with an empty rule_id renders a guarded
    title (no trailing colon-space)."""
    draft = pytest.importorskip("repo_audit.issues.draft")
    from repo_audit.schema.report import ReportMeta, ScanReport

    finding = Finding(
        dimension="security", severity="critical", confidence="confirmed",
        evidence_type="static",
        evidence=Evidence(tool="repo", output_snippet="snippet"),
        confidence_caveat="Static only.",
        rule_id="", recommendation="Fix it.", source_tool="repo",
        file="src/auth.py", line=10,
    )
    report = ScanReport(
        meta=ReportMeta(
            repo_slug=_CANON_SLUG, commit_sha="a" * 40,
            scan_date=date.today(), tool_version="0.1.0",
        ),
        findings=[finding],
    )
    drafts = draft.build_drafts(report)
    solos = [d for d in drafts if d.kind == "solo"]
    assert len(solos) == 1
    assert not solos[0].title.rstrip().endswith(":")
    assert "(unlabeled)" in solos[0].title


def test_rollup_fingerprint_distinct_and_order_stable(tmp_path):
    """The rollup identity (CR-01) is membership-aware: it differs from
    members[0]'s solo fingerprint and is stable regardless of member order."""
    fingerprint = pytest.importorskip("repo_audit.issues.fingerprint")

    a = _make_finding(
        dimension="quality", severity="major", confidence="confirmed",
        rule_id="Q-1", file="src/a.py",
    )
    b = _make_finding(
        dimension="quality", severity="major", confidence="confirmed",
        rule_id="Q-2", file="src/b.py",
    )
    fp_a = fingerprint.build_fingerprint(a)
    fp_b = fingerprint.build_fingerprint(b)

    rollup = fingerprint.build_rollup_fingerprint([fp_a, fp_b], dimension="quality")
    # Distinct from any single member's fingerprint (no false-duplicate drop).
    assert rollup != fp_a
    assert rollup != fp_b
    # Order-stable: member order does not change the identity.
    assert rollup == fingerprint.build_rollup_fingerprint(
        [fp_b, fp_a], dimension="quality"
    )
    # Membership churn IS visible: dropping a member changes the identity.
    assert rollup != fingerprint.build_rollup_fingerprint(
        [fp_a], dimension="quality"
    )


def test_dedup_skips_open_marker_match(tmp_path, monkeypatch):
    """A draft whose fingerprint matches an OPEN issue's marker is skipped as a
    duplicate; a non-matching fingerprint is kept."""
    dedup = pytest.importorskip("repo_audit.issues.dedup")

    monkeypatch.setattr(dedup, "run_tool", fake_run_tool)
    existing = dedup.fetch_open_fingerprints(
        Path(tmp_path), owner_repo=_CANON_OWNER_REPO
    )
    # The canned ``gh issue list`` open issue carries this fingerprint.
    assert _OPEN_ISSUE_FINGERPRINT in existing
    assert dedup.is_duplicate(_OPEN_ISSUE_FINGERPRINT, existing) is True
    assert dedup.is_duplicate("nomatch000000", existing) is False


def test_find_duplicate_match_without_url_is_still_skip(tmp_path):
    """WR-04: a marker match on an issue whose JSON lacks ``url`` still returns a
    non-None value (a placeholder) so the caller treats it as a duplicate."""
    dedup = pytest.importorskip("repo_audit.issues.dedup")

    open_issues = [
        {"number": 9, "body": f"x <!-- arch-fingerprint: {_OPEN_ISSUE_FINGERPRINT} -->"}
    ]  # NOTE: no "url" key.
    result = dedup.find_duplicate(_OPEN_ISSUE_FINGERPRINT, open_issues)
    assert result is not None
    # A genuine miss still returns None.
    assert dedup.find_duplicate("nomatch000000", open_issues) is None


def test_origin_parse_all_four_forms():
    """All four ``git remote`` URL forms parse to the same owner/repo."""
    targeting = pytest.importorskip("repo_audit.issues.targeting")

    forms = [
        "git@github.com:BradGregersen/repo-audit.git",
        "https://github.com/BradGregersen/repo-audit.git",
        "https://github.com/BradGregersen/repo-audit",
        "ssh://git@github.com/BradGregersen/repo-audit.git",
    ]
    parsed = {targeting.parse_origin(form) for form in forms}
    assert parsed == {_CANON_OWNER_REPO}


def test_guard_blocks_wrong_repo(tmp_path):
    """The identity guard REFUSES when the sidecar's repo_slug does not match
    the resolved origin owner/repo (D-10 wrong-repo guard)."""
    targeting = pytest.importorskip("repo_audit.issues.targeting")

    repo = _make_repo_wrong_origin(tmp_path)
    _write_sidecar(repo)  # sidecar speaks for repo-audit; origin does not.
    with pytest.raises(targeting.IdentityGuardError):
        targeting.assert_target_matches(repo, scanned_slug=_CANON_SLUG)


def test_self_file_allowed_when_target_matches(tmp_path):
    """Self-filing IS allowed when the target origin matches the scanned repo
    (repo-audit auditing itself)."""
    targeting = pytest.importorskip("repo_audit.issues.targeting")

    repo = _make_repo(tmp_path)  # canonical origin
    _write_sidecar(repo)
    # Must not raise — origin owner/repo matches the scanned slug.
    targeting.assert_target_matches(repo, scanned_slug=_CANON_SLUG)


# --------------------------------------------------------------------------- #
# Small shared helper used by the gated bodies above. Defined late so it does  #
# not import any issues.* symbol at module load (keeps the file import-clean). #
# --------------------------------------------------------------------------- #
def loader_report(repo: Path):
    """Load the sidecar via issues.loader (only called inside gated tests)."""
    loader = pytest.importorskip("repo_audit.issues.loader")
    return loader.load_latest_sidecar(repo)
