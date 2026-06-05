"""DAST lane (DAST-01) — opt-in ZAP baseline (passive) scan.

The lane whose entire reason to exist is the no-inference guarantee (SC4 /
Pitfall 7): the ZAP target enters the ``-t`` argv from EXACTLY ONE source,
``cfg.target_url`` (read from ``.repo-audit.yaml`` at call time). No CLI
flag, no default, no repo-derivation. No configured target → the lane refuses
(``status='unavailable'``).

Task-1 surface (Plan 16-05): the config reader + the ZAP-JSON normalizer.
``run_dast`` (the scope guard + invocation + post-pass runtime-drop guard) lands
in Task 2 of this plan.
"""
from __future__ import annotations

from repo_audit.adapters.dast.config import DastConfig, read_dast_config
from repo_audit.adapters.dast.zap_json import zap_json_to_findings

__all__ = ["DastConfig", "read_dast_config", "zap_json_to_findings"]
