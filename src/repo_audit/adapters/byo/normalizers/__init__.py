"""Per-tool JSON->Finding normalizers for the 2 BYO commercial tools that do
NOT emit SARIF (BYO-02, Plan 16-06).

The RESEARCH correction: the commercial-tool normalizer surface is 3, not 6.
CodeQL / Semgrep Pro / Snyk (test + code) / ggshield all emit SARIF natively and
reuse the shared ``sarif_to_findings`` path — they need NO per-tool normalizer.
Only **Socket.dev** and **SonarQube** emit tool-native JSON, so only these two
need a tiny normalizer here (ZAP's JSON normalizer lives in Plan 16-05).

Both normalizers copy the SARIF parser's ``_result_to_finding`` recipe (candidate
cap, ``evidence_type='static'``, ``confidence='candidate'``, ``source_tool`` tag,
faithful severity preserved in ``parsed_value``) so a JSON-sourced Finding is
structurally identical to a SARIF-sourced one. Both are DEFENSIVE: a missing key
skips that entry, a non-dict doc returns ``[]``, and neither EVER raises.
"""
from repo_audit.adapters.byo.normalizers.socket_json import (
    socket_json_to_findings,
)
from repo_audit.adapters.byo.normalizers.sonar_json import (
    sonar_json_to_findings,
)

__all__ = ["socket_json_to_findings", "sonar_json_to_findings"]
