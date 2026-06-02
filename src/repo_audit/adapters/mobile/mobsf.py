"""MOB-03 Tier-3a (9-T3a) — MobSF Docker static client + redacting mapper (Plan 09-03).

Opt-in (``--mobsf``) binary-level static analysis of a SHIPPED debug APK. MobSF
catches secrets/issues that source scanning misses because they only exist in the
built artifact (resource strings, smali, packaged config). This module is the
Docker REST client + the report mapper.

Two seams, mirroring the Phase-7/8 native-JSON precedent (osv/grype/squawk):

  * :func:`map_mobsf_report` — maps MobSF's ``StaticAnalyzerAndroid`` ``report_json``
    (NOT SARIF — a bespoke shape with ``secrets`` / ``possible_secrets`` lists and a
    ``findings`` map) to candidate/static security Findings. This is the MOST
    DANGEROUS untrusted-output boundary in the phase: ``report_json`` carries RAW
    secret VALUES. EVERY such value is routed through the redaction chokepoint
    (:func:`_redact_span` → ``[REDACTED:N]``) BEFORE a Finding is constructed —
    the raw string NEVER enters ``output_snippet`` or ``parsed_value`` (T-09-04 /
    SCH-08 defense-in-depth).

  * :func:`collect_mobsf` — the Docker lifecycle: start MobSF behind ``run_tool``
    (FND-04, shell=False) with a per-run ``MOBSF_API_KEY`` generated via
    ``secrets.token_hex`` (NEVER scraped from logs/UI, T-09-09), upload → scan →
    pull ``report_json`` → delete_scan over stdlib ``urllib`` (no new HTTP dep),
    then a guaranteed ``try/finally`` ``docker stop`` teardown (T-09-03, Pitfall 3)
    even on an HTTP error. Absent Docker / absent APK / any HTTP error degrades to
    ``unavailable`` / ``timeout`` and NEVER hangs.

The ``image_ref`` (a pinned ``…@sha256:<digest>``) is passed IN by Plan 05 — this
module accepts it as a parameter and never hard-codes a digest (Plan 05 owns the
pin; T-09-10). Registration (``@register_adapter("mobile")``) is also Plan 05's.
"""
from __future__ import annotations

import json
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from repo_audit.adapters.base import AdapterResult
from repo_audit.adapters.supabase.footguns import _redact_span
from repo_audit.adapters.toolops import EXEC_FAILED, TIMED_OUT, run_tool
from repo_audit.schema.enums import Severity
from repo_audit.schema.finding import Evidence, Finding

_SOURCE_TOOL = "mobsf"
_SOURCE_ADAPTER = "mobile"
_DIMENSION = "security"

# MobSF finding ``severity`` -> mapped Severity. "high" is capped at "major"
# (SCH-04 forbids candidate + {critical, blocker}; only Phase-17 corroboration
# may promote). Unknown/absent levels default to "info".
_MOBSF_SEVERITY: dict[str, Severity] = {
    "high": "major",
    "warning": "minor",
    "info": "info",
}
_DEFAULT_SEVERITY: Severity = "info"

# rule_id for the redacted hardcoded-secret findings (the secrets/possible_secrets
# lists). Distinct from the slugified per-finding rule ids below.
_SECRET_RULE_ID = "mobsf_hardcoded_secret"

# Metadata keys we are willing to copy onto parsed_value from a MobSF finding's
# ``metadata`` block. We DELIBERATELY do not copy metadata blindly — only these
# describe the rule (severity/taxonomy), never a value that could carry a secret.
_SAFE_METADATA_KEYS: frozenset[str] = frozenset(
    {"cvss", "cwe", "owasp-mobile", "masvs"}
)


def _severity_for(level: object) -> Severity:
    """Map a MobSF severity string to a capped Severity (default info)."""
    return _MOBSF_SEVERITY.get(str(level).strip().lower(), _DEFAULT_SEVERITY)


def _slugify_rule_id(title: str) -> str:
    """Turn a MobSF finding title into a stable snake_case rule_id."""
    out: list[str] = []
    prev_us = False
    for ch in title.strip().lower():
        if ch.isalnum():
            out.append(ch)
            prev_us = False
        elif not prev_us:
            out.append("_")
            prev_us = True
    slug = "".join(out).strip("_")
    return slug or "mobsf_finding"


def _secret_finding(raw_secret: str, source_key: str) -> Finding:
    """Build ONE redacted Finding for a raw secret string from report_json.

    The raw value is passed through :func:`_redact_span` → ``[REDACTED:N]`` and
    the literal NEVER enters ``output_snippet`` or ``parsed_value``. Only the
    LENGTH and provenance survive (T-09-04 / SCH-08 defense-in-depth).
    """
    redacted = _redact_span(raw_secret)
    recommendation = (
        "a hardcoded secret was detected in the APK; verify and rotate — "
        "value redacted. Cross-check the MOB-02 bundled-secrets pass; MobSF "
        "flags the presence of a secret-shaped string in the built artifact, "
        "not that the value is live."
    )
    caveat = (
        "MobSF static secret match in the built APK (value redacted at the "
        "adapter boundary); confirm the secret is real and reachable before "
        "acting."
    )
    return Finding(
        dimension=_DIMENSION,
        severity="major",  # SCH-04 candidate cap forbids critical/blocker
        file=None,
        line=None,
        evidence=Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=f"hardcoded secret in APK {redacted}",
            parsed_value={
                "redacted_len": len(raw_secret),
                "source": source_key,
            },
        ),
        evidence_type="static",
        confidence="candidate",
        recommendation=recommendation,
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_TOOL,
        rule_id=_SECRET_RULE_ID,
        confidence_caveat=caveat,
    )


def _safe_metadata(metadata: object) -> dict[str, object]:
    """Copy ONLY the allowlisted taxonomy keys from a finding's metadata.

    MobSF ``metadata`` can carry a free-form ``description`` (and, defensively,
    anything else) — we never copy it blindly into ``parsed_value`` because it
    could echo a secret-bearing string. Only severity/taxonomy keys survive.
    """
    if not isinstance(metadata, dict):
        return {}
    return {k: v for k, v in metadata.items() if k in _SAFE_METADATA_KEYS}


def _issue_finding(title: str, body: object) -> Finding | None:
    """Map one entry of report_json["findings"] to a Finding (or None)."""
    if not isinstance(body, dict):
        return None
    severity = _severity_for(body.get("severity"))
    rule_id = _slugify_rule_id(title)

    # file/line from the first entry of the ``files`` map when present. MobSF's
    # ``files`` is a {path: location-hint} map; the path is the key. There is no
    # reliable line number in the static report shape, so line stays None.
    file_path: str | None = None
    files = body.get("files")
    if isinstance(files, dict) and files:
        first_key = next(iter(files))
        file_path = str(first_key)

    parsed_value: dict[str, object] = {
        "title": title,
        "severity": str(body.get("severity", "")),
    }
    parsed_value.update(_safe_metadata(body.get("metadata")))

    recommendation = (
        f"MobSF static analysis flagged '{title}' in the built APK; review the "
        "referenced artifact and verify the issue before acting (binary-level "
        "static signal, not runtime-confirmed)."
    )
    return Finding(
        dimension=_DIMENSION,
        severity=severity,
        file=file_path,
        line=None,
        evidence=Evidence(
            tool=_SOURCE_TOOL,
            output_snippet=f"mobsf: {title}",
            parsed_value=parsed_value,
        ),
        evidence_type="static",
        confidence="candidate",
        recommendation=recommendation,
        source_tool=_SOURCE_TOOL,
        source_collector=_SOURCE_TOOL,
        rule_id=rule_id,
    )


def map_mobsf_report(report_json: dict) -> list[Finding]:
    """Map a MobSF ``report_json`` document to redacted static security Findings.

    Consumes the ``StaticAnalyzerAndroid`` shape (NOT SARIF — a bespoke native
    JSON, mirroring the Phase-7/8 osv/grype/squawk native-JSON precedent):

      * ``secrets`` / ``possible_secrets`` / ``hardcoded_secrets`` — lists of RAW
        secret strings. Each becomes ONE Finding with the value REDACTED via
        :func:`_redact_span` → ``[REDACTED:N]`` BEFORE construction; the raw
        string NEVER reaches ``output_snippet`` or ``parsed_value`` (T-09-04).
        ``rule_id="mobsf_hardcoded_secret"``, ``severity="major"``.
      * ``findings`` — a ``{title: {severity, files, metadata}}`` map. Each maps
        through :data:`_MOBSF_SEVERITY` ("high"→major capped, "warning"→minor,
        "info"/unknown→info), ``rule_id`` = slugified title, file from the first
        ``files`` key. Only allowlisted taxonomy metadata is copied (never a raw
        ``description`` that could echo a secret).

    Every Finding: ``source_tool="mobsf"``, ``dimension="security"``,
    ``evidence_type="static"``, ``confidence="candidate"``, severity ≤ "major".
    Empty/missing keys → ``[]`` (never crashes).

    Args:
        report_json: the parsed MobSF report_json document.

    Returns:
        One :class:`Finding` per raw secret and per ``findings`` entry, all with
        every raw secret redacted at this boundary.
    """
    if not isinstance(report_json, dict):
        return []

    findings: list[Finding] = []

    # Raw-secret lists → redacted findings (the dangerous boundary).
    for source_key in ("secrets", "possible_secrets", "hardcoded_secrets"):
        raw_list = report_json.get(source_key) or []
        if not isinstance(raw_list, (list, tuple)):
            continue
        for raw_secret in raw_list:
            if not isinstance(raw_secret, str) or not raw_secret.strip():
                continue
            findings.append(_secret_finding(raw_secret, source_key))

    # The ``findings`` map → per-issue findings.
    issues = report_json.get("findings")
    if isinstance(issues, dict):
        for title, body in issues.items():
            finding = _issue_finding(str(title), body)
            if finding is not None:
                findings.append(finding)

    return findings


# Naming aliases — the Wave-0 test (_map_report) probes these names in order.
report_json_to_findings = map_mobsf_report
map_report_json = map_mobsf_report
map_mobsf_json = map_mobsf_report


# --- Task 2: Docker REST client + collect_mobsf orchestration ----------------

# Default overall wall-clock bound for a MobSF static scan (Pitfall 3 / T-09-03).
_MOBSF_TIMEOUT_SECONDS: float = 600.0
# Bound for the container START (docker run -d returns the id quickly).
_DOCKER_START_TIMEOUT_SECONDS: float = 120.0
# Bound for the container STOP (teardown must itself never hang).
_DOCKER_STOP_TIMEOUT_SECONDS: float = 60.0
# Wall-clock cap for the readiness poll loop after the container starts.
_READINESS_WAIT_SECONDS: float = 60.0
# Per-HTTP-call socket timeout so no single REST call can hang the tier.
_HTTP_TIMEOUT_SECONDS: float = 30.0
# Host port the MobSF REST API is published on (container always listens on 8000).
_HOST_PORT: int = 8000
_CONTAINER_PORT: int = 8000

# The conventional debug-APK output path (Open-Q1). A Gradle/Expo Android build
# writes the debug APK here; we rglob for it so a monorepo subdir is found.
_DEBUG_APK_GLOB = "android/app/build/outputs/apk/debug/*.apk"


class _MobsfHttpError(Exception):
    """An HTTP/JSON error talking to the MobSF REST API (mapped to unavailable)."""


def find_debug_apk(repo: Path, supplied: Path | None) -> Path | None:
    """Return an existing debug APK to scan, or ``None``.

    Resolution order (Open-Q1):
      1. ``supplied`` if it exists (caller passed ``--mobsf-apk`` / a build out).
      2. the first match of the conventional Gradle/Expo debug-APK path under
         ``repo`` (``android/app/build/outputs/apk/debug/*.apk``).
      3. ``None`` — no APK; the caller degrades to ``unavailable`` (never builds
         one here; producing a build artifact is out of this module's scope).
    """
    if supplied is not None and Path(supplied).exists():
        return Path(supplied)
    try:
        for match in Path(repo).rglob(_DEBUG_APK_GLOB):
            if match.is_file():
                return match
    except OSError:
        return None
    return None


def _base_url(host_port: int) -> str:
    return f"http://127.0.0.1:{host_port}"


def _http_post(
    url: str,
    *,
    api_key: str,
    fields: dict[str, str] | None = None,
    file_field: tuple[str, str, bytes] | None = None,
) -> dict:
    """POST to a MobSF endpoint via stdlib ``urllib`` and return parsed JSON.

    No new HTTP dependency (T — stdlib urllib keeps the surface shell-free and
    minimal). ``file_field`` is ``(field_name, filename, content)`` for the
    multipart upload; ``fields`` are form-encoded for the other calls. Every
    call carries the ``Authorization: <api_key>`` header and a socket timeout so
    it cannot hang. Any error raises :class:`_MobsfHttpError`.
    """
    headers = {"Authorization": api_key}
    if file_field is not None:
        boundary = uuid.uuid4().hex
        field_name, filename, content = file_field
        body = bytearray()
        body += f"--{boundary}\r\n".encode()
        body += (
            f'Content-Disposition: form-data; name="{field_name}"; '
            f'filename="{filename}"\r\n'
        ).encode()
        body += b"Content-Type: application/octet-stream\r\n\r\n"
        body += content
        body += f"\r\n--{boundary}--\r\n".encode()
        data = bytes(body)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    else:
        data = urllib.parse.urlencode(fields or {}).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as resp:
            raw = resp.read()
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        raise _MobsfHttpError(f"POST {url} failed: {type(exc).__name__}: {exc}") from exc
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError) as exc:
        raise _MobsfHttpError(f"POST {url} returned non-JSON: {exc}") from exc


def _wait_ready(base_url: str, *, deadline: float) -> bool:
    """Poll the MobSF root until it answers (bounded by ``deadline``).

    A short-timeout GET against the API root; once the server answers without a
    connection error we consider it ready. Returns ``False`` if the wall-clock
    ``deadline`` passes first — the caller then degrades to ``unavailable``
    rather than hanging.
    """
    while time.perf_counter() < deadline:
        try:
            request = urllib.request.Request(base_url + "/", method="GET")
            with urllib.request.urlopen(request, timeout=5.0):
                return True
        except urllib.error.HTTPError:
            # The server answered (any HTTP status) → it is up.
            return True
        except (urllib.error.URLError, socket.timeout, OSError):
            time.sleep(2.0)
    return False


def _docker_stop(container_id: str, *, env: dict[str, str], cwd: str | Path) -> None:
    """Guaranteed-teardown ``docker stop`` (Pitfall 3) — never raises.

    Always invoked from the ``finally`` of :func:`collect_mobsf`. ``--rm`` on the
    run means a stopped container is also removed, so this single call both stops
    and reaps. Routed through ``run_tool`` (shell=False); any failure is
    swallowed — teardown best-effort must not mask the primary result.
    """
    if not container_id:
        return
    try:
        run_tool(
            ["docker", "stop", container_id],
            env=env,
            cwd=cwd,
            timeout_seconds=_DOCKER_STOP_TIMEOUT_SECONDS,
        )
    except Exception:  # noqa: BLE001 — teardown is best-effort, never raises
        pass


def collect_mobsf(
    apk: Path | None,
    *,
    env: dict[str, str],
    image_ref: str,
    timeout_seconds: float = _MOBSF_TIMEOUT_SECONDS,
) -> AdapterResult:
    """Run MobSF (Docker, static) against ``apk`` and map the report (redacted).

    Lifecycle (guaranteed-teardown, T-09-03 / Pitfall 3):
      1. ``apk is None`` → ``unavailable`` ("no debug APK") immediately.
      2. Generate a per-run API key via ``secrets.token_hex(32)`` (T-09-09 —
         NEVER scraped from logs/UI), inject it via ``MOBSF_API_KEY`` env on the
         container.
      3. Start the container through ``run_tool`` (``docker run -d --rm`` with
         the pinned ``image_ref``, ``MOBSF_API_KEY`` + ``MOBSF_API_ONLY`` env).
         ``EXEC_FAILED`` → ``unavailable`` (docker not installed / daemon down);
         capture the container id from stdout.
      4. ``try``: poll readiness (bounded), then upload → scan → report_json →
         delete_scan over stdlib ``urllib``; map the report (redacted).
         ``finally``: ALWAYS ``docker stop`` the container (even on HTTP error).
      5. Any HTTP/JSON/timeout error → ``unavailable`` / ``timeout``; a top-level
         backstop guarantees the function never raises.

    Args:
        apk: an EXISTING debug APK path (or ``None`` → unavailable). This module
            never builds one.
        env: child environment passed verbatim to every ``run_tool`` docker call.
        image_ref: the pinned MobSF image (``…@sha256:<digest>``), supplied by
            Plan 05. Never hard-coded here (T-09-10 — Plan 05 owns the pin).
        timeout_seconds: overall wall-clock bound for the scan phase.

    Returns:
        ``AdapterResult`` — ``status="ok"`` with redacted findings on success,
        else ``status="unavailable"|"timeout"``. NEVER raises, NEVER hangs.
    """
    base_kwargs = dict(
        source_adapter=_SOURCE_ADAPTER,
        source_tool=_SOURCE_TOOL,
        dimension=_DIMENSION,
    )

    if apk is None:
        return AdapterResult(
            status="unavailable",
            notes="no debug APK (pass --mobsf-build to produce one)",
            **base_kwargs,
        )

    try:
        apk = Path(apk)
        if not apk.exists():
            return AdapterResult(
                status="unavailable",
                notes=f"debug APK not found at {apk}",
                **base_kwargs,
            )

        # Per-run, unguessable API key — injected via env, never scraped (T-09-09).
        api_key = secrets.token_hex(32)

        start = run_tool(
            [
                "docker", "run", "-d", "--rm",
                "-p", f"{_HOST_PORT}:{_CONTAINER_PORT}",
                "-e", f"MOBSF_API_KEY={api_key}",
                "-e", "MOBSF_API_ONLY=1",
                image_ref,
            ],
            env=env,
            cwd=apk.parent,
            timeout_seconds=_DOCKER_START_TIMEOUT_SECONDS,
        )
        if start.returncode == EXEC_FAILED:
            return AdapterResult(
                status="unavailable",
                notes="docker not available to run MobSF (not installed / daemon down)",
                **base_kwargs,
            )
        if start.returncode == TIMED_OUT:
            return AdapterResult(
                status="timeout",
                notes=f"docker run exceeded {_DOCKER_START_TIMEOUT_SECONDS:.0f}s",
                **base_kwargs,
            )
        if start.returncode != 0:
            return AdapterResult(
                status="unavailable",
                notes=f"docker run failed: {start.stderr.strip()[:200]}",
                **base_kwargs,
            )

        container_id = start.stdout.strip().splitlines()[0].strip() if start.stdout.strip() else ""
        if not container_id:
            return AdapterResult(
                status="unavailable",
                notes="docker run returned no container id",
                **base_kwargs,
            )

        base_url = _base_url(_HOST_PORT)
        try:
            ready = _wait_ready(
                base_url,
                deadline=time.perf_counter() + _READINESS_WAIT_SECONDS,
            )
            if not ready:
                return AdapterResult(
                    status="unavailable",
                    notes=f"MobSF did not become ready within {_READINESS_WAIT_SECONDS:.0f}s",
                    **base_kwargs,
                )

            report_json = _run_static_scan(base_url, api_key=api_key, apk=apk)
            findings = map_mobsf_report(report_json)
            return AdapterResult(
                findings=findings,
                status="ok",
                notes=f"mobsf static: {len(findings)} finding(s) (secrets redacted)",
                scanned_paths=[str(apk)],
                **base_kwargs,
            )
        except _MobsfHttpError as exc:
            return AdapterResult(
                status="unavailable",
                notes=f"MobSF REST error: {str(exc)[:200]}",
                **base_kwargs,
            )
        finally:
            # GUARANTEED teardown — runs even on an HTTP error above (Pitfall 3).
            _docker_stop(container_id, env=env, cwd=apk.parent)
    except Exception as exc:  # noqa: BLE001 — absolute never-raise backstop
        return AdapterResult(
            status="unavailable",
            notes=f"mobsf collection failed: {type(exc).__name__}: {exc}",
            **base_kwargs,
        )


def _run_static_scan(base_url: str, *, api_key: str, apk: Path) -> dict:
    """upload → scan → report_json → delete_scan over the MobSF REST API.

    Returns the parsed ``report_json`` document (the ``StaticAnalyzerAndroid``
    shape :func:`map_mobsf_report` consumes). Raises :class:`_MobsfHttpError` on
    any HTTP/JSON failure (mapped to ``unavailable`` by the caller). The
    ``delete_scan`` cleanup is best-effort and never masks a successful report.
    """
    content = apk.read_bytes()
    upload = _http_post(
        base_url + "/api/v1/upload",
        api_key=api_key,
        file_field=("file", apk.name, content),
    )
    file_hash = str(upload.get("hash", "")).strip()
    if not file_hash:
        raise _MobsfHttpError("MobSF upload returned no hash")

    _http_post(base_url + "/api/v1/scan", api_key=api_key, fields={"hash": file_hash})
    report = _http_post(
        base_url + "/api/v1/report_json", api_key=api_key, fields={"hash": file_hash}
    )

    # Best-effort cleanup of the scan inside MobSF — never masks the report.
    try:
        _http_post(
            base_url + "/api/v1/delete_scan", api_key=api_key, fields={"hash": file_hash}
        )
    except _MobsfHttpError:
        pass

    return report


def run_mobsf(
    apk_path: Path | None = None,
    *,
    repo: Path | None = None,
    image_ref: str | None = None,
    timeout_seconds: float = _MOBSF_TIMEOUT_SECONDS,
) -> AdapterResult:
    """Convenience entry point: resolve an APK, build a default env, run MobSF.

    Mirrors ``mobsfscan.run_mobsfscan`` — a thin wrapper so the standalone/live
    path (and the Wave-0 ``test_unavailable``) can invoke the collector without
    plumbing a scan env. Plan 05 calls :func:`collect_mobsf` directly with the
    shared scan env + the pinned image instead.

    With ``apk_path=None`` and no ``repo`` (the docker-absent test path), this
    short-circuits to ``unavailable`` ("no debug APK") without ever touching
    docker — honest and hang-free.
    """
    from repo_audit.adapters.cache_env import build_scan_env, scan_tempdir

    apk = apk_path
    if apk is None and repo is not None:
        apk = find_debug_apk(Path(repo), None)

    if apk is None:
        return AdapterResult(
            status="unavailable",
            source_adapter=_SOURCE_ADAPTER,
            source_tool=_SOURCE_TOOL,
            dimension=_DIMENSION,
            notes="no debug APK (pass --mobsf-build to produce one)",
        )

    with scan_tempdir() as tempdir:
        env = build_scan_env(tempdir)
        return collect_mobsf(
            Path(apk),
            env=env,
            image_ref=image_ref or "",
            timeout_seconds=timeout_seconds,
        )


__all__ = [
    "_MOBSF_SEVERITY",
    "map_mobsf_report",
    "report_json_to_findings",
    "map_report_json",
    "map_mobsf_json",
    "collect_mobsf",
    "find_debug_apk",
    "run_mobsf",
]
