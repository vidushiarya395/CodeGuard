"""One scan = Agent 1 (Semgrep + Bandit) and Agent 2 (rule checks, taint check + AI review), run side by side.

This is what the CLI and the API call. Secret values are masked in every finding here
(codeguard.redact), whichever detector reported it. The findings are still raw (unverified); the Verifier
(Agent 3) is added in a later phase.

A problem in one detector never stops the scan: it becomes a FAILED tool run with a message, and
every other detector still runs.
"""

from __future__ import annotations

import tempfile
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from codeguard.agents import standard_scanner
from codeguard.agents.ai_mistake_finder import ALL_CHECKS, run_rule_checks
from codeguard.agents.llm_review import LLM_CHECKS, run_llm_review
from codeguard.agents.standard_scanner import (
    ScanInputError,
    check_snippet,
    internal_filename,
    rename_file,
    safe_filename,
)
from codeguard.config import Settings, get_settings
from codeguard.cwe import CweGroups, get_cwe_groups
from codeguard.inputs import ZipInputError, extract_zip
from codeguard.llm.client import LLMClient
from codeguard.models import ScanResult, ToolRun, ToolState
from codeguard.redact import mask_secrets
from codeguard.rulechecks.netclient import PackageIndex
from codeguard.scanners.base import ScannerOutcome

__all__ = ["ScanInputError", "scan_code", "scan_path", "scan_zip"]

AGENT1_TOOLS = ("semgrep", "bandit")


def _failed(tools: tuple[str, ...], what: str, exc: BaseException) -> list[ScannerOutcome]:
    msg = f"{what} failed unexpectedly ({type(exc).__name__}: {exc}). The other checks still ran."
    return [ScannerOutcome(ToolRun(tool=t, state=ToolState.FAILED, message=msg)) for t in tools]


def _outcomes(job: Future, tools: tuple[str, ...], what: str) -> list[ScannerOutcome]:
    try:
        return job.result()
    except Exception as exc:
        return _failed(tools, what, exc)


def scan_path(
    path: Path,
    settings: Settings | None = None,
    groups: CweGroups | None = None,
    index: PackageIndex | None = None,
    display_name: str | None = None,
    llm: LLMClient | None = None,
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
    with ThreadPoolExecutor(max_workers=3) as pool:
        agent1 = pool.submit(standard_scanner.scan_path, path, settings, groups)
        agent2 = pool.submit(run_rule_checks, path, settings, groups, index, None, display_name)
        agent2_ai = pool.submit(run_llm_review, path, settings, groups, llm, display_name)
        try:
            scanners = agent1.result()
        except Exception as exc:
            scanners = ScanResult(target=str(path), tool_runs=[o.run for o in _failed(AGENT1_TOOLS, "Standard scanner", exc)])
        rule_outcomes = _outcomes(agent2, ALL_CHECKS, "Rule checks") + _outcomes(agent2_ai, LLM_CHECKS, "AI review")

    if display_name:
        rename_file(scanners, path.name, display_name)
    findings = [*scanners.findings, *(f for o in rule_outcomes for f in o.findings)]
    tool_runs = [*scanners.tool_runs, *(o.run for o in rule_outcomes)]
    # Mask secrets once, here, so every output (CLI, JSON, API, exports) gets masked data.
    try:
        mask_secrets(findings, path, groups, settings.rules_dir, display_name)
    except Exception as exc:
        # Never show evidence that might hold an unmasked secret: drop the code snippets instead.
        for f in findings:
            f.evidence.matched_code = None
        tool_runs.append(
            ToolRun(
                tool="redaction",
                state=ToolState.FAILED,
                message=f"Secret masking failed ({type(exc).__name__}); code snippets were removed from the report.",
            )
        )
    findings.sort(key=lambda f: (f.file, f.line_start, f.detectors[0].value, f.evidence.rule_ids))
    return ScanResult(
        target=str(path),
        findings=findings,
        tool_runs=tool_runs,
        duration_s=round(time.perf_counter() - start, 3),
    )


def scan_code(
    code: str,
    filename: str | None = None,
    settings: Settings | None = None,
    groups: CweGroups | None = None,
    index: PackageIndex | None = None,
    llm: LLMClient | None = None,
) -> ScanResult:
    """Scan pasted code. It is written to a temporary folder (never executed) and scanned there."""
    settings = settings or get_settings()
    check_snippet(code, settings)
    name = safe_filename(filename)
    with tempfile.TemporaryDirectory(prefix="codeguard-scan-", ignore_cleanup_errors=True) as tmp:
        file_path = Path(tmp) / internal_filename()
        file_path.write_text(code, encoding="utf-8", newline="")
        result = scan_path(file_path, settings, groups, index, display_name=name, llm=llm)
    result.target = name
    return result


def scan_zip(
    archive: Path,
    settings: Settings | None = None,
    groups: CweGroups | None = None,
    index: PackageIndex | None = None,
    llm: LLMClient | None = None,
) -> ScanResult:
    """Scan the Python files inside a zip archive. They are unpacked to a temporary folder (never run)."""
    archive = Path(archive)
    if not archive.is_file():
        raise ScanInputError(f"Path not found: {archive}")
    with tempfile.TemporaryDirectory(prefix="codeguard-zip-", ignore_cleanup_errors=True) as tmp:
        root = Path(tmp) / "src"
        root.mkdir()
        try:
            report = extract_zip(archive, root)
        except ZipInputError as exc:
            raise ScanInputError(str(exc)) from exc
        result = scan_path(root, settings, groups, index, llm=llm)
    result.target = archive.name
    result.notes = [f"{report.python_files} Python file(s) taken from {archive.name}.", *report.notes()]
    return result
