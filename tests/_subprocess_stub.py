"""Canned ``subprocess`` stand-in for the five external-tool spawn seams.

Why this exists
---------------
The deterministic suite used to spawn real external binaries — gitleaks (14×
per scan-runner test), npx, syft, grype, osv-scanner, scc — on every test that
reached the scan pipeline. Warm, one such test cost ~14 s; cold (no grype DB,
no osv DB, no npx cache) it cost ~132 s. A stranger cloning the repo gets the
cold number on every one of the ~26 test files that reach ``run_scan``, which
is why the full suite took 25+ minutes and never finished.

The seam is NOT ``toolops.run_tool``. ~30 modules do
``from repo_audit.adapters.toolops import run_tool`` — a from-import, so
each binds its own reference and patching ``toolops.run_tool`` does not reach
them. Instead we patch one level lower: every spawning module does a
module-level ``import subprocess``, so rebinding *that module's* ``subprocess``
attribute (``monkeypatch.setattr(mod, "subprocess", FakeSubprocess())``)
intercepts the spawn without touching the global ``subprocess`` module.

Design contract
---------------
* **Only the measured-expensive binaries are intercepted.** A binary with no
  canned response is delegated to the real ``subprocess``. That keeps the blast
  radius to the handful of tools that actually cost wall time and leaves every
  other tool alone — including the fake executables some tests build for
  themselves and every ``pytest-subprocess`` (``fp``) registration.
* **An absent binary still looks absent.** If a *known* ``argv[0]`` does not
  resolve on disk or PATH, the stub raises ``FileNotFoundError`` exactly like
  the real module. ``run_tool`` maps that to ``EXEC_FAILED`` and collectors map
  it to ``unavailable`` — the honest "tool not installed" path is preserved.
* **A present binary returns a parseable empty result**, never garbage. A
  parse failure would flip findings from ``unavailable`` to ``failed`` and
  silently change what tests assert, so each known binary gets a canned
  response that parses cleanly into its collector's *empty-result* shape.
* **Sentinel returncodes are never forged.** ``run_tool`` reserves ``-1``
  (exec failed) and ``-2`` (timed out) as structural sentinels it computes
  itself. The stub only ever returns real tool exit statuses.
* **Side effects that the caller reads back are performed.** Several tools are
  invoked with an output-file flag and the caller reads the file afterwards
  (``gitleaks --report-path``, ``syft -o cyclonedx-json=<path>``). The stub
  writes those files, because a missing file is a different code path.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess as _real_subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

# Re-exported verbatim from the real module so ``except mod.subprocess.X``
# and ``isinstance`` checks behave identically under the stub.
PIPE = _real_subprocess.PIPE
DEVNULL = _real_subprocess.DEVNULL
STDOUT = _real_subprocess.STDOUT
TimeoutExpired = _real_subprocess.TimeoutExpired
SubprocessError = _real_subprocess.SubprocessError
CalledProcessError = _real_subprocess.CalledProcessError
CompletedProcess = _real_subprocess.CompletedProcess


@dataclass
class Response:
    """What a stubbed binary "returns"."""

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


# --- Canned payloads -------------------------------------------------------

# A structurally valid, zero-result SARIF 2.1.0 log. Parses through
# ``sarif_to_findings`` to [] and still carries tool.driver.version so
# ``_extract_scanner_version``-style helpers find what they look for.
def _empty_sarif(tool_name: str) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": "0.0.0-test-stub",
                            "informationUri": "https://example.invalid",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }
    )


# A minimal but valid empty CycloneDX 1.5 document.
_EMPTY_CYCLONEDX = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {"type": "application", "name": "syft", "version": "0.0.0-test-stub"}
                ]
            },
            "component": {
                "bom-ref": "test-stub-root",
                "type": "file",
                "name": "test-stub-root",
            },
        },
        "components": [],
        "dependencies": [],
    }
)


def _flag_value(argv: Sequence[str], flag: str) -> str | None:
    """Return the value following ``flag`` in ``argv``, or None."""
    for i, token in enumerate(argv):
        if token == flag and i + 1 < len(argv):
            return argv[i + 1]
        if token.startswith(flag + "="):
            return token.split("=", 1)[1]
    return None


def _write(path_str: str | None, payload: str) -> None:
    """Best-effort write of a canned artifact the caller will read back."""
    if not path_str:
        return
    try:
        path = Path(path_str)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    except OSError:
        # The caller treats a missing artifact as 'unavailable', which is a
        # legitimate outcome; never raise out of the stub.
        pass


# --- Per-binary responders -------------------------------------------------


def _gitleaks(argv: Sequence[str]) -> Response:
    """gitleaks 8.x — always "no findings".

    ``gitleaks stdin`` reports on stdout; ``gitleaks git|dir --report-path P``
    writes a JSON report to ``P`` and the caller reads ``P`` back, so the file
    must exist or the caller takes the no-report branch.
    """
    report_path = _flag_value(argv, "--report-path")
    if report_path and report_path != "-":
        _write(report_path, "[]")
        return Response(returncode=0, stdout="", stderr="")
    return Response(returncode=0, stdout="[]", stderr="")


def _osv_scanner(argv: Sequence[str]) -> Response:
    """osv-scanner — no vulnerabilities, in whichever format was requested."""
    fmt = (_flag_value(argv, "--format") or "json").lower()
    if fmt == "sarif":
        return Response(stdout=_empty_sarif("osv-scanner"))
    return Response(stdout=json.dumps({"results": []}))


def _grype(argv: Sequence[str]) -> Response:
    """grype — no matches. ``db update`` is a no-op success."""
    if "db" in argv:
        return Response(stdout="", stderr="")
    fmt = (_flag_value(argv, "-o") or _flag_value(argv, "--output") or "json").lower()
    if fmt == "sarif":
        return Response(stdout=_empty_sarif("grype"))
    return Response(
        stdout=json.dumps(
            {
                "matches": [],
                "source": None,
                "distro": {},
                "descriptor": {"name": "grype", "version": "0.0.0-test-stub"},
            }
        )
    )


def _syft(argv: Sequence[str]) -> Response:
    """syft — an empty CycloneDX SBOM, written to the ``-o fmt=path`` target."""
    out = _flag_value(argv, "-o") or _flag_value(argv, "--output") or ""
    if "=" in out:
        _write(out.split("=", 1)[1], _EMPTY_CYCLONEDX)
        return Response(stdout="", stderr="")
    return Response(stdout=_EMPTY_CYCLONEDX)


def _scc(argv: Sequence[str]) -> Response:
    """scc — an empty per-language array (a valid, parseable zero-LOC result)."""
    return Response(stdout="[]")


def _semgrep(argv: Sequence[str]) -> Response:
    """semgrep — no results and no errors."""
    fmt_sarif = "--sarif" in argv
    if fmt_sarif:
        return Response(stdout=_empty_sarif("semgrep"))
    return Response(stdout=json.dumps({"results": [], "errors": [], "paths": {}}))


def _node_runner(argv: Sequence[str]) -> Response:
    """npx / npm / node — success with no output."""
    return Response(stdout="", stderr="")


DEFAULT_RESPONDERS: dict[str, Callable[[Sequence[str]], Response]] = {
    "gitleaks": _gitleaks,
    "osv-scanner": _osv_scanner,
    "grype": _grype,
    "syft": _syft,
    "scc": _scc,
    "semgrep": _semgrep,
    "npx": _node_runner,
    "npm": _node_runner,
    "node": _node_runner,
}


def _binary_key(argv0: str) -> str:
    """Normalise ``argv[0]`` to a bare binary name for responder lookup."""
    name = os.path.basename(str(argv0))
    if name.endswith(".exe"):
        name = name[: -len(".exe")]
    # Vendored binaries are shipped per-platform, e.g. ``scc-linux-amd64``.
    for known in DEFAULT_RESPONDERS:
        if name == known or name.startswith(known + "-") or name.startswith(known + "_"):
            return known
    return name


def _binary_is_present(argv0: str) -> bool:
    """True when the real binary would have been exec-able.

    Keeps the "tool not installed → unavailable" path honest: a binary that is
    genuinely absent must still raise ``FileNotFoundError`` under the stub.
    """
    text = str(argv0)
    if os.sep in text or (os.altsep and os.altsep in text):
        return Path(text).exists()
    return shutil.which(text) is not None


class _FakePopen:
    """Minimal ``Popen`` satisfying ``toolops.run_tool``'s actual usage.

    ``run_tool`` uses ``communicate(timeout=…)``, ``returncode``, and — on the
    timeout ladder — ``terminate()``/``kill()``. Nothing else is touched, so
    nothing else is faked.
    """

    def __init__(self, argv: Sequence[str], response: Response) -> None:
        self.args = list(argv)
        self._response = response
        self.returncode: int | None = None
        self.pid = -1
        self.stdout = None
        self.stderr = None

    def communicate(self, input=None, timeout=None):  # noqa: A002 - Popen's name
        self.returncode = self._response.returncode
        return self._response.stdout, self._response.stderr

    def wait(self, timeout=None) -> int:
        self.returncode = self._response.returncode
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = self._response.returncode

    def kill(self) -> None:
        self.returncode = self._response.returncode

    def send_signal(self, sig) -> None:
        self.returncode = self._response.returncode

    def __enter__(self) -> "_FakePopen":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False


@dataclass
class FakeSubprocess:
    """A drop-in stand-in for the ``subprocess`` module inside one module.

    Args:
        responders: per-binary overrides, keyed by bare binary name. Merged
            over :data:`DEFAULT_RESPONDERS`.
        passthrough: binary names that should be executed for real (escape
            hatch for a test that must observe genuine tool behaviour).
        default: response for a binary that is present but has no responder.
    """

    responders: dict[str, Callable[[Sequence[str]], Response]] = field(
        default_factory=dict
    )
    passthrough: frozenset[str] = frozenset()
    default: Response = field(default_factory=Response)
    calls: list[list[str]] = field(default_factory=list)

    # Module-level names the patched modules reference.
    PIPE = PIPE
    DEVNULL = DEVNULL
    STDOUT = STDOUT
    TimeoutExpired = TimeoutExpired
    SubprocessError = SubprocessError
    CalledProcessError = CalledProcessError
    CompletedProcess = CompletedProcess

    # -- internals ---------------------------------------------------------

    def _resolve(self, argv) -> tuple[str, Response] | None:
        """Return ``(key, response)``, or None when the call is a passthrough."""
        if isinstance(argv, str):
            # Every seam in this codebase passes list[str] (shell=False is a
            # hard rule); a str argv is a caller bug, not ours to paper over.
            raise TypeError(f"stubbed subprocess requires a list argv; got {argv!r}")
        command = [str(a) for a in argv]
        if not command:
            raise ValueError("empty argv")
        key = _binary_key(command[0])
        if key in self.passthrough:
            return None
        responder = self.responders.get(key) or DEFAULT_RESPONDERS.get(key)
        if responder is None:
            # Not a binary this stub knows how to fake cheaply. Hand it to the
            # real subprocess module rather than inventing a result — the
            # unknown tools are all cheap (absent ones fail instantly) and some
            # tests install their own fakes at this seam.
            return None
        self.calls.append(command)
        if not _binary_is_present(command[0]):
            raise FileNotFoundError(2, "No such file or directory", command[0])
        return key, responder(command)

    # -- the subprocess surface --------------------------------------------

    def Popen(self, argv, *args, **kwargs):  # noqa: N802 - mirrors subprocess
        resolved = self._resolve(argv)
        if resolved is None:
            return _real_subprocess.Popen(argv, *args, **kwargs)
        _key, response = resolved
        return _FakePopen(argv, response)

    def run(self, argv, *args, **kwargs):
        resolved = self._resolve(argv)
        if resolved is None:
            return _real_subprocess.run(argv, *args, **kwargs)
        _key, response = resolved
        capture = kwargs.get("capture_output") or (
            kwargs.get("stdout") is not None or kwargs.get("stderr") is not None
        )
        completed = CompletedProcess(
            args=list(argv),
            returncode=response.returncode,
            stdout=response.stdout if capture else None,
            stderr=response.stderr if capture else None,
        )
        if kwargs.get("check") and completed.returncode != 0:
            raise CalledProcessError(
                completed.returncode,
                completed.args,
                output=completed.stdout,
                stderr=completed.stderr,
            )
        return completed

    def check_output(self, argv, *args, **kwargs):
        kwargs.setdefault("capture_output", True)
        kwargs["check"] = True
        return self.run(argv, *args, **kwargs).stdout

    def call(self, argv, *args, **kwargs) -> int:
        return self.run(argv, *args, **kwargs).returncode

    def check_call(self, argv, *args, **kwargs) -> int:
        kwargs["check"] = True
        return self.run(argv, *args, **kwargs).returncode


# Modules that spawn external binaries and are stubbed by the autouse fixture.
#
# ``meta.git_status`` is deliberately ABSENT: its only spawn is ``git``, which
# cost 0.02 s across an entire scan and whose tests depend on real repository
# state. Stubbing it would buy nothing and lie about something tests check.
STUBBED_MODULES: tuple[str, ...] = (
    "repo_audit.adapters.toolops",
    "repo_audit.render.secret_lint",
    "repo_audit.adapters.typescript.refresh",
    "repo_audit.collectors.loc_inventory",
)


__all__ = [
    "FakeSubprocess",
    "Response",
    "DEFAULT_RESPONDERS",
    "STUBBED_MODULES",
]
