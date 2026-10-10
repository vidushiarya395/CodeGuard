"""Semgrep Community Edition runner (ruleset p/python by default)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from codeguard.config import REPO_ROOT, Settings
from codeguard.cwe import CweGroups, normalize_cwe
from codeguard.models import Detector, Evidence, Finding, ToolRun, ToolState
from codeguard.scanners.base import (
    SKIP_DIRS,
    ScannerOutcome,
    ScanTarget,
    SourceReader,
    ToolTimeout,
    failed_run,
    humanize,
    last_lines,
    missing_run,
    normalize_rel_path,
    run_command,
    timeout_run,
)

TOOL = "semgrep"

INSTALL_HINT = (
    "Install it in its own environment from the repo root:  "
    "python -m venv .venv-semgrep; .\\.venv-semgrep\\Scripts\\python -m pip install semgrep==1.179.0  "
    "(or set CODEGUARD_SEMGREP_PATH in .env). If Semgrep will not run on Windows, use WSL; see README."
)


def find_semgrep(settings: Settings) -> str | None:
    """Explicit setting first, then the project's .venv-semgrep, then PATH."""
    if settings.semgrep_path:
        return settings.semgrep_path if Path(settings.semgrep_path).is_file() else None
    scripts = "Scripts" if sys.platform == "win32" else "bin"
    exe = "semgrep.exe" if sys.platform == "win32" else "semgrep"
    local = REPO_ROOT / ".venv-semgrep" / scripts / exe
    if local.is_file():
        return str(local)
    return shutil.which("semgrep")


def build_command(exe: str, settings: Settings, target: ScanTarget) -> list[str]:
    cmd = [
        exe,
        "scan",
        "--config",
        settings.semgrep_config,
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        # Ignore "# nosemgrep" comments: scanned code must not be able to switch checks off.
        "--disable-nosem",
    ]
    for d in SKIP_DIRS:
        cmd += ["--exclude", d]
    cmd.append(target.arg)
    return cmd


def run_semgrep(target: ScanTarget, settings: Settings, groups: CweGroups) -> ScannerOutcome:
    exe = find_semgrep(settings)
    if exe is None:
        where = f" at CODEGUARD_SEMGREP_PATH={settings.semgrep_path}" if settings.semgrep_path else ""
        return missing_run(TOOL, f"Semgrep was not found{where}. {INSTALL_HINT}")

    # The version is read from Semgrep's JSON output (a separate --version call costs seconds).
    version = None
    try:
        res = run_command(build_command(exe, settings, target), cwd=target.cwd, timeout_s=settings.scanner_timeout_s)
    except FileNotFoundError:
        return missing_run(TOOL, f"Semgrep could not be started from {exe}. {INSTALL_HINT}")
    except OSError as exc:
        return failed_run(TOOL, f"Semgrep could not be started: {exc}", version)
    except ToolTimeout:
        return timeout_run(TOOL, settings.scanner_timeout_s, version)

    return parse_semgrep_output(res.stdout, res.stderr, res.returncode, target.cwd, groups, version, res.duration_s)


def parse_semgrep_output(
    stdout: str,
    stderr: str,
    returncode: int,
    root: Path,
    groups: CweGroups,
    version: str | None = None,
    duration_s: float = 0.0,
) -> ScannerOutcome:
    try:
        data = json.loads(stdout[stdout.index("{") :]) if "{" in stdout else None
    except ValueError:
        data = None

    if not isinstance(data, dict) or "results" not in data:
        detail = last_lines(stderr) or last_lines(stdout) or "no output"
        hint = ""
        if any(w in (stderr + stdout).lower() for w in ("download", "connection", "network", "resolve", "registry")):
            hint = " Semgrep needs internet access to download its rules (p/python) from the Semgrep registry."
        return failed_run(TOOL, f"Semgrep failed (exit code {returncode}): {detail}.{hint}", version, duration_s)

    file_errors: list[str] = []
    for err in data.get("errors") or []:
        if not isinstance(err, dict):
            continue
        where = err.get("path") or ""
        msg = (err.get("message") or err.get("type") or "error").strip().splitlines()[0]
        file_errors.append(f"{normalize_rel_path(where)}: {msg}" if where else msg)

    reader = SourceReader(root)
    findings: list[Finding] = []
    for r in data.get("results") or []:
        f = _to_finding(r, reader, groups)
        if f is not None:
            findings.append(f)

    # Exit codes 0 and 1 mean "ran fine". Anything else with results means a partial scan.
    message = None
    if returncode not in (0, 1):
        message = f"Semgrep finished with exit code {returncode}; results may be incomplete."
        if file_errors:
            message += f" First error: {file_errors[0]}"
    run = ToolRun(
        tool=TOOL,
        state=ToolState.OK,
        version=version or data.get("version"),
        message=message,
        duration_s=round(duration_s, 3),
        findings_count=len(findings),
        file_errors=file_errors,
    )
    return ScannerOutcome(run, findings)


def _to_finding(r: dict, reader: SourceReader, groups: CweGroups) -> Finding | None:
    try:
        rel = normalize_rel_path(str(r["path"]))
        start = int(r["start"]["line"])
        end = int(r.get("end", {}).get("line", start))
        rule_id = str(r["check_id"])
    except (KeyError, TypeError, ValueError):
        return None
    extra = r.get("extra") or {}
    meta = extra.get("metadata") or {}

    cwes = [c for c in (normalize_cwe(x) for x in _as_list(meta.get("cwe"))) if c]
    cwe = cwes[0] if cwes else None

    refs = [str(x) for x in _as_list(meta.get("references")) if x]
    for key in ("source", "source-rule-url"):
        if meta.get(key):
            refs.append(str(meta[key]))

    evidence = Evidence(
        rule_ids=[rule_id],
        matched_code=reader.lines(rel, start, max(end, start)),
        messages=[f"[semgrep {rule_id.rsplit('.', 1)[-1]}] {str(extra.get('message', '')).strip()}"],
        references=list(dict.fromkeys(refs)),
        tool_severity={TOOL: str(extra["severity"])} if extra.get("severity") else {},
        tool_confidence={TOOL: str(meta["confidence"])} if meta.get("confidence") else {},
    )
    return Finding(
        file=rel,
        line_start=max(start, 1),
        line_end=max(end, start, 1),
        cwe=cwe,
        cwe_group=groups.group_of(cwe),
        title=humanize(rule_id.rsplit(".", 1)[-1]),
        detectors=[Detector.SEMGREP],
        evidence=evidence,
    )


def _as_list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
