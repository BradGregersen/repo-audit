"""VER-02 / SC2 — tiered corroboration promotes candidate→corroborated (RAISES only).

Made real in Plan 17-01 Task 2.

``tiered_corroborate(findings, *, reachability_fn=check_reachable, repo_path=None,
line_window=3) -> tuple[list[Finding], list[VerificationRecord]]``:

  * tier-1 identity  — same normalized rule_id, ≥2 distinct source_tools.
  * tier-2 locus     — same file + line±window + same dimension, ≥2 distinct tools.
  * tier-3 coarse    — is_corroborated (same dim+file, tool-diversity ≥2).
  * reachability     — single-tool candidate + check_reachable==True corroborates.
  * runtime          — evidence_type=='runtime' auto-corroborates.

RAISES only: len(out)==len(in); never deletes; never touches severity; strongest
tier wins; deterministic on shuffled input.
"""
from __future__ import annotations

import random

from repo_audit.verification.corroborate import (
    is_corroborated,
    tiered_corroborate,
)


def _conf(findings):
    return [f.confidence for f in findings]


def test_tier_promotion_raises_only(fake_finding):
    """VER-02/SC2: identity agreement promotes candidate→corroborated; len unchanged."""
    a = fake_finding(family="sca", source_tool="osv", rule_id="CVE-2026-0001")
    b = fake_finding(family="sca_grype", source_tool="grype", rule_id="CVE-2026-0001")
    out, records = tiered_corroborate([a, b])

    # Count conserved — never deletes.
    assert len(out) == 2
    # Both promoted to corroborated.
    assert all(c == "corroborated" for c in _conf(out))
    # Severity untouched.
    assert [f.severity for f in out] == [a.severity, b.severity]
    # A VerificationRecord records the winning tier.
    by_tier = {r.corroboration_tier for r in records}
    assert "identity" in by_tier


def test_single_tool_not_corroborated(fake_finding):
    """A lone candidate with no 2nd signal stays candidate (never inflated)."""
    a = fake_finding(family="sca", source_tool="osv", rule_id="CVE-ONLY")
    out, records = tiered_corroborate([a])
    assert len(out) == 1
    assert out[0].confidence == "candidate"


def test_identity_requires_two_distinct_tools(fake_finding):
    """Same rule_id from the SAME tool twice is NOT corroboration (no diversity)."""
    a = fake_finding(source_tool="osv", rule_id="CVE-DUP", file="a.py", line=1)
    b = fake_finding(source_tool="osv", rule_id="CVE-DUP", file="b.py", line=2)
    out, _ = tiered_corroborate([a, b])
    assert all(f.confidence == "candidate" for f in out)


def test_locus_tier(fake_finding):
    """Same file + line within window + same dimension + 2 tools → locus tier."""
    a = fake_finding(source_tool="semgrep", rule_id="R1", file="src/x.ts", line=10)
    b = fake_finding(source_tool="snyk", rule_id="R2", file="src/x.ts", line=12)
    out, records = tiered_corroborate([a, b], line_window=3)
    assert all(f.confidence == "corroborated" for f in out)
    assert any(r.corroboration_tier == "locus" for r in records)


def test_locus_outside_window_falls_to_coarse(fake_finding):
    """Same file + same dimension + 2 tools but line far apart still corroborates
    via the coarse tier (same dim+file, diversity>=2)."""
    a = fake_finding(source_tool="semgrep", rule_id="R1", file="src/x.ts", line=10)
    b = fake_finding(source_tool="snyk", rule_id="R2", file="src/x.ts", line=900)
    out, records = tiered_corroborate([a, b], line_window=3)
    assert all(f.confidence == "corroborated" for f in out)
    assert any(r.corroboration_tier == "coarse" for r in records)


def test_runtime_auto_corroborates(fake_finding):
    """D-17-07: a lone runtime finding auto-corroborates (tier=runtime)."""
    a = fake_finding(source_tool="zap", rule_id="DAST-1", evidence_type="runtime")
    out, records = tiered_corroborate([a])
    assert out[0].confidence == "corroborated"
    assert any(r.corroboration_tier == "runtime" for r in records)


def test_reachability_signal_corroborates(fake_finding):
    """D-17-02: a single-tool candidate + reachable==True corroborates (tier=reachability)."""
    a = fake_finding(source_tool="semgrep", rule_id="R1", file="src/a.py", line=1)

    def _always_reachable(finding, repo_path):
        return True

    out, records = tiered_corroborate(
        [a], reachability_fn=_always_reachable, repo_path="/tmp/x"
    )
    assert out[0].confidence == "corroborated"
    assert any(r.corroboration_tier == "reachability" for r in records)


def test_reachability_false_never_promotes(fake_finding):
    """A negative/unknown reachability never promotes (stays candidate, never deleted)."""
    a = fake_finding(source_tool="semgrep", rule_id="R1", file="src/a.py", line=1)

    def _never_reachable(finding, repo_path):
        return False

    out, _ = tiered_corroborate(
        [a], reachability_fn=_never_reachable, repo_path="/tmp/x"
    )
    assert len(out) == 1
    assert out[0].confidence == "candidate"


def test_strongest_tier_wins(fake_finding):
    """When identity AND coarse both apply, identity (strongest) is recorded."""
    a = fake_finding(source_tool="osv", rule_id="CVE-X", file="src/a.py", line=5)
    b = fake_finding(source_tool="grype", rule_id="CVE-X", file="src/a.py", line=5)
    out, records = tiered_corroborate([a, b])
    assert all(f.confidence == "corroborated" for f in out)
    assert all(r.corroboration_tier == "identity" for r in records if r.corroboration_tier != "none")


def test_static_critical_promotion_preserves_caveat(fake_finding):
    """Pitfall 3: promoting a static-critical finding keeps a non-empty caveat
    (the SAFE-01 validator re-runs on model_copy and must not raise)."""
    caveat = "SAFE-01: runtime not verified."
    a = fake_finding(
        source_tool="osv",
        rule_id="CVE-CRIT",
        severity="critical",
        confidence="corroborated",  # already promoted so critical is schema-valid
        evidence_type="static",
        confidence_caveat=caveat,
    )
    b = fake_finding(
        source_tool="grype",
        rule_id="CVE-CRIT",
        severity="critical",
        confidence="corroborated",
        evidence_type="static",
        confidence_caveat=caveat,
    )
    out, _ = tiered_corroborate([a, b])
    for f in out:
        assert f.severity == "critical"
        assert f.confidence_caveat and f.confidence_caveat.strip()


def test_deterministic_on_shuffled_input(fake_finding):
    """SC-5: shuffled input → identical output ordering + identical tiers."""
    findings = [
        fake_finding(source_tool="osv", rule_id=f"CVE-{i}", file=f"f{i}.py", line=i)
        for i in range(6)
    ] + [
        fake_finding(source_tool="grype", rule_id=f"CVE-{i}", file=f"f{i}.py", line=i)
        for i in range(6)
    ]

    def _run(seq):
        out, records = tiered_corroborate(list(seq))
        return (
            [(f.source_tool, f.rule_id, f.confidence) for f in out],
            sorted((r.finding_ref, r.corroboration_tier) for r in records),
        )

    baseline = _run(findings)
    for seed in (1, 2, 3, 99):
        shuffled = findings[:]
        random.Random(seed).shuffle(shuffled)
        assert _run(shuffled) == baseline


def test_is_corroborated_still_exported(fake_finding):
    """Tier-3 is the factored is_corroborated; it lives here now."""
    a = fake_finding(source_tool="osv", file="src/a.py", dimension="security")
    b = fake_finding(source_tool="grype", file="src/a.py", dimension="security")
    assert is_corroborated(a, [a, b]) is True


def test_fileless_findings_do_not_coarse_corroborate(fake_finding):
    """Two file-less rows in one dimension from different tools are not agreement."""
    a = fake_finding(
        dimension="quality", file=None, line=None,
        source_tool="lighthouse", rule_id="perf-summary",
    )
    b = fake_finding(
        dimension="quality", file=None, line=None,
        source_tool="metro", rule_id="bundle-size-summary",
    )
    out, records = tiered_corroborate([a, b])
    assert all(f.confidence == "candidate" for f in out)
    assert not any(r.corroboration_tier == "coarse" for r in records)


def test_fileless_findings_still_corroborate_by_identity(fake_finding):
    """Two tools reporting the same rule with no file still agree by identity."""
    a = fake_finding(file=None, line=None, source_tool="osv", rule_id="CVE-2026-0002")
    b = fake_finding(file=None, line=None, source_tool="grype", rule_id="CVE-2026-0002")
    out, records = tiered_corroborate([a, b])
    assert all(f.confidence == "corroborated" for f in out)
    assert any(r.corroboration_tier == "identity" for r in records)
