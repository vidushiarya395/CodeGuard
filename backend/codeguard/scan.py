"""One scan = Agent 1 (Semgrep + Bandit) and Agent 2's rule checks, run side by side.

This is what the CLI and the API call. Secret values are masked in every finding here
(codeguard.redact), whichever detector reported it. The findings are still raw (unverified); the Verifier
(Agent 3) is added in a later phase.
"""

from __future__ import annotations

import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from codeguard.agents import standard_scanner
from codeguard.agents.ai_mistake_finder import run_rule_checks
from codeguard.agents.standard_scanner import (
    ScanInputError,
    check_snippet,
    internal_filename,
    rename_file,
    safe_filename,
)
from codeguard.config import Settings, get_settings
from codeguard.cwe import CweGroups, get_cwe_groups
from codeguard.models import ScanResult
from codeguard.redact import mask_secrets
from codeguard.rulechecks.netclient import PackageIndex

__all__ = ["ScanInputError", "scan_code", "scan_path"]


def scan_path(
    path: Path,
    settings: Settings | None = None,
    groups: CweGroups | None = None,
    index: PackageIndex | None = None,
    display_name: str | None = None,
) -> ScanResult:
    """Scan a file or folder. For a single file, `display_name` is the name shown in the report and
    seen by the rule checks, when the file on disk has a different (internal) name."""
    settings = settings or get_settings()
    groups = groups or get_cwe_groups()
    path = Path(path)
    if not path.exists():
        raise ScanInputError(f"Path not found: {path}")
    if not path.is_file():
        display_name = None

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        agent1 = pool.submit(standard_scanner.scan_path, path, settings, groups)
        agent2 = pool.submit(run_rule_checks, path, settings, groups, index, None, display_name)
        scanners = agent1.result()
        rule_outcomes = agent2.result()

    if display_name:
        rename_file(scanners, path.name, display_name)
    findings = [*scanners.findings, *(f for o in rule_outcomes for f in o.findings)]
    # Mask secrets once, here, so every output (CLI, JSON, API, exports) gets masked data.
    mask_secrets(findings, path, groups, settings.rules_dir, display_name)
    findings.sort(key=lambda f: (f.file, f.line_start, f.detectors[0].value, f.evidence.rule_ids))
    return ScanResult(
        target=str(path),
        findings=findings,
        tool_runs=[*scanners.tool_runs, *(o.run for o in rule_outcomes)],
        duration_s=round(time.perf_counter() - start, 3),
    )


def scan_code(
    code: str,
    filename: str | None = None,
    settings: Settings | None = None,
    groups: CweGroups | None = None,
    index: PackageIndex | None = None,
) -> ScanResult:
    """Scan pasted code. It is written to a temporary folder (never executed) and scanned there."""
    settings = settings or get_settings()
    check_snippet(code, settings)
    name = safe_filename(filename)
    with tempfile.TemporaryDirectory(prefix="codeguard-scan-", ignore_cleanup_errors=True) as tmp:
        file_path = Path(tmp) / internal_filename()
        file_path.write_text(code, encoding="utf-8", newline="")
        result = scan_path(file_path, settings, groups, index, display_name=name)
    result.target = name
    return result

