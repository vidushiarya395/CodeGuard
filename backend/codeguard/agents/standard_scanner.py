"""Agent 1: Standard Scanner (no AI).

Runs Semgrep (p/python) and Bandit side by side and collects their findings unchanged.
It does not merge, de-duplicate or rank findings; that is the Verifier's job (Agent 3).
"""

from __future__ import annotations

import re
import secrets
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from codeguard.config import Settings, get_settings
from codeguard.cwe import CweGroups, get_cwe_groups
from codeguard.models import ScanResult
from codeguard.scanners import ScannerOutcome, ScanTarget, run_bandit, run_semgrep

DEFAULT_SNIPPET_NAME = "snippet.py"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]")


class ScanInputError(ValueError):
    """The thing the user asked us to scan is not valid (missing path, too many lines...)."""


def scan_path(path: Path, settings: Settings | None = None, groups: CweGroups | None = None) -> ScanResult:
    settings = settings or get_settings()
    groups = groups or get_cwe_groups()
    path = Path(path)
    if not path.exists():
        raise ScanInputError(f"Path not found: {path}")

    target = ScanTarget.from_path(path)
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        semgrep_job = pool.submit(run_semgrep, target, settings, groups)
        bandit_job = pool.submit(run_bandit, target, settings, groups)
        outcomes: list[ScannerOutcome] = [semgrep_job.result(), bandit_job.result()]

    findings = [f for o in outcomes for f in o.findings]
    findings.sort(key=lambda f: (f.file, f.line_start, f.detectors[0].value, f.evidence.rule_ids))
    return ScanResult(
        target=str(path),
        findings=findings,
        tool_runs=[o.run for o in outcomes],
        duration_s=round(time.perf_counter() - start, 3),
    )


def safe_filename(name: str | None) -> str:
    """Keep only a plain file name ending in .py, so pasted input can't choose where it is written."""
    base = Path((name or "").replace("\\", "/")).name
    base = _SAFE_NAME.sub("_", base).lstrip(".")
    if not base:
        return DEFAULT_SNIPPET_NAME
    if not base.endswith(".py"):
        base += ".py"
    return base[:100]


def check_snippet(code: str, settings: Settings) -> None:
    """Reject empty or too-long pasted code."""
    if not code.strip():
        raise ScanInputError("The code is empty.")
    line_count = len(code.splitlines())
    if line_count > settings.max_paste_lines:
        raise ScanInputError(
            f"The code has {line_count} lines; the limit is {settings.max_paste_lines}."
        )


def scan_code(
    code: str, filename: str | None = None, settings: Settings | None = None, groups: CweGroups | None = None
) -> ScanResult:
    """Scan pasted code. It is written to a temporary folder (never executed) and scanned there."""
    settings = settings or get_settings()
    check_snippet(code, settings)

    name = safe_filename(filename)
    with tempfile.TemporaryDirectory(prefix="codeguard-scan-", ignore_cleanup_errors=True) as tmp:
        file_path = Path(tmp) / internal_filename()
        file_path.write_text(code, encoding="utf-8", newline="")
        result = scan_path(file_path, settings, groups)
    rename_file(result, file_path.name, name)
    result.target = name
    return result


def internal_filename() -> str:
    """The on-disk name for code the user hands us as a single file (paste now; uploads later).

    Never the user's own name: a file called string.py or os.py could shadow a module that a
    scanner imports and so get executed. The user's name is only used in the report.
    """
    return f"cg_{secrets.token_hex(8)}.py"


def rename_file(result: ScanResult, internal: str, shown: str) -> None:
    """Show the user's file name instead of the internal one in findings, file errors and messages."""
    for f in result.findings:
        if f.file == internal:
            f.file = shown
    for run in result.tool_runs:
        run.file_errors = [shown + e[len(internal) :] if e.startswith(internal + ":") else e for e in run.file_errors]
        if run.message:
            run.message = run.message.replace(internal, shown)
