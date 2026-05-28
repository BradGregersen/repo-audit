"""Vendored binaries (scc) shipped inside the wheel.

Per D-34, scc is vendored (4 platform builds) because its JSON output is
stable across minor versions. gitleaks is intentionally NOT vendored
(D-35) — see collectors/secret_detection.py for rationale.

Binary layout:
    vendor/scc/{linux-x86_64,linux-arm64,macos-x86_64,macos-arm64}/scc
    vendor/scc/LICENSE-scc.txt        (MIT, ships per upstream requirement)
    vendor/scc/SHA256SUMS.txt         (supply-chain integrity proof)
"""
