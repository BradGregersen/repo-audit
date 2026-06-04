"""quality_depth config reader contract (Plan 15-01, Task 2) — ACTIVE now.

``read_quality_depth_config(repo_path)`` is shipped THIS plan, so these tests run
(not skip). They pin: documented defaults on a no-config repo, per-repo override
layering, missing-file → defaults, malformed-block → defaults (never raises), and
the offline fixture shapes the Wave-1 parser tests will consume.
"""
from __future__ import annotations

import json
from pathlib import Path

from repo_audit.adapters.quality_depth.config import (
    QualityDepthConfig,
    read_quality_depth_config,
)


def test_defaults_when_no_config_file(tmp_path: Path) -> None:
    """A repo with no .repo-audit.yaml → all documented defaults."""
    cfg = read_quality_depth_config(tmp_path)
    assert cfg.live_url is None
    assert cfg.web_budget_bytes == 256000
    assert cfg.rn_budget_bytes == 512000
    assert cfg.regression_pct == 10.0
    assert cfg.regression_floor_bytes == 10240
    assert cfg.rn_entry_file == "index.js"


def test_live_url_override_layers_on_top(write_qd_config) -> None:
    """A configured quality_depth.live_url overrides the None default."""
    repo = write_qd_config('  live_url: "https://staging.example.com"\n')
    cfg = read_quality_depth_config(repo)
    assert cfg.live_url == "https://staging.example.com"
    # Untouched keys keep their defaults.
    assert cfg.web_budget_bytes == 256000


def test_budget_overrides_layer(write_qd_config) -> None:
    """Budget / threshold overrides layer over the defaults."""
    repo = write_qd_config(
        "  web_budget_bytes: 128000\n"
        "  rn_budget_bytes: 1048576\n"
        "  regression_pct: 25\n"
        "  regression_floor_bytes: 5120\n"
        '  rn_entry_file: "index.ts"\n'
    )
    cfg = read_quality_depth_config(repo)
    assert cfg.web_budget_bytes == 128000
    assert cfg.rn_budget_bytes == 1048576
    assert cfg.regression_pct == 25.0
    assert cfg.regression_floor_bytes == 5120
    assert cfg.rn_entry_file == "index.ts"
    assert cfg.live_url is None


def test_missing_block_yields_defaults(tmp_path: Path) -> None:
    """A .repo-audit.yaml with NO quality_depth block → defaults."""
    (tmp_path / ".repo-audit.yaml").write_text(
        "architecture:\n  duplication:\n    floor_pct: 3\n",
        encoding="utf-8",
    )
    cfg = read_quality_depth_config(tmp_path)
    assert cfg.live_url is None
    assert cfg.web_budget_bytes == 256000


def test_malformed_yaml_yields_defaults(tmp_path: Path) -> None:
    """A poisoned / malformed user YAML degrades to defaults, never raises."""
    (tmp_path / ".repo-audit.yaml").write_text(
        "quality_depth: [unbalanced\n",
        encoding="utf-8",
    )
    cfg = read_quality_depth_config(tmp_path)
    assert cfg == QualityDepthConfig()


def test_unknown_override_key_is_ignored(write_qd_config) -> None:
    """An unrecognized key in the block is dropped (extra='forbid' never trips)."""
    repo = write_qd_config(
        "  live_url: \"https://x.test\"\n  bogus_future_key: 7\n"
    )
    cfg = read_quality_depth_config(repo)
    assert cfg.live_url == "https://x.test"


def test_config_is_frozen() -> None:
    """The resolved config is immutable for the scan (frozen model)."""
    import pydantic

    cfg = QualityDepthConfig()
    try:
        cfg.live_url = "https://mutated.test"  # type: ignore[misc]
    except pydantic.ValidationError:
        return
    except Exception:  # noqa: BLE001 — frozen may raise a non-pydantic error
        return
    raise AssertionError("QualityDepthConfig should be frozen/immutable")


# --------------------------------------------------------------------------- #
# Offline fixture shape contracts (Wave-1 parser inputs)
# --------------------------------------------------------------------------- #
def test_axe_fixture_shape(load_json) -> None:
    """axe_results.json parses to a dict with a non-empty violations list."""
    doc = load_json("axe_results.json")
    assert isinstance(doc, dict)
    assert isinstance(doc["violations"], list)
    assert len(doc["violations"]) >= 2
    first = doc["violations"][0]
    for key in ("id", "impact", "tags", "help", "helpUrl", "nodes"):
        assert key in first


def test_lighthouse_fixture_shape(load_json) -> None:
    """lighthouse_lhr.json has categories.performance.score + the four metrics."""
    doc = load_json("lighthouse_lhr.json")
    assert isinstance(doc["categories"]["performance"]["score"], (int, float))
    audits = doc["audits"]
    for audit_id in (
        "largest-contentful-paint",
        "cumulative-layout-shift",
        "total-blocking-time",
        "total-byte-weight",
    ):
        assert isinstance(audits[audit_id]["numericValue"], (int, float))


def test_eslint_a11y_fixture_shape(load_json) -> None:
    """eslint_a11y.json carries >=1 jsx-a11y/* and >=1 react-native-a11y/* rule."""
    doc = load_json("eslint_a11y.json")
    rule_ids = [
        msg["ruleId"]
        for file_result in doc
        for msg in file_result["messages"]
    ]
    assert any(rid.startswith("jsx-a11y/") for rid in rule_ids)
    assert any(rid.startswith("react-native-a11y/") for rid in rule_ids)


def test_rn_bundle_fixture_has_deterministic_size(rn_bundle_path: Path) -> None:
    """index.android.bundle is a real file with a positive, on-disk byte size."""
    assert rn_bundle_path.is_file()
    size = rn_bundle_path.stat().st_size
    assert size > 0
    # The stat() read is deterministic: it equals the actual byte content length.
    assert size == len(rn_bundle_path.read_bytes())
