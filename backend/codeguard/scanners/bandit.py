"""Bandit runner."""

from __future__ import annotations

import glob
import importlib.util
import json
import shutil
import sys
from functools import lru_cache
from pathlib import Path

from codeguard.config import Settings
from codeguard.cwe import CweGroups, normalize_cwe
from codeguard.models import Detector, Evidence, Finding, ToolRun, ToolState
from codeguard.scanners.base import (
    SKIP_DIRS,
    ScannerOutcome,
    ScanTarget,
    SourceReader,
    ToolTimeout,
    failed_run,
    last_lines,
    missing_run,
    neutral_dir,
    run_command,
    timeout_run,
    to_rel_path,
)

TOOL = "bandit"

INSTALL_HINT = "Install it into the project environment:  python -m pip install -e backend  (Bandit is a dependency)."


def find_bandit() -> list[str] | None:
    """Prefer Bandit from the same Python environment as CodeGuard, then PATH."""
    if importlib.util.find_spec("bandit") is not None:
        # -P: do not put the working directory on sys.path, so a scanned string.py or os.py can
        # never be imported (run) in place of the real module.
        return [sys.executable, "-P", "-m", "bandit"]
    exe = shutil.which("bandit")
    return [exe] if exe else None


@lru_cache(maxsize=1)
def bandit_version() -> str | None:
    try:
        from importlib.metadata import version

        return version("bandit")
    except Exception:
        return None


def build_command(base: list[str], target: ScanTarget, out_file: Path) -> list[str]:
    # Bandit matches excludes against full paths. Anchor them at the scan root so a parent folder
    # of the target (e.g. C:\work\vendor\myproj) never hides the files being scanned.
    root = glob.escape(Path(target.root).as_posix())
    if "," in root:  # -x is comma-separated; fall back to unanchored patterns
        excludes = ",".join(f"*/{d}/*" for d in SKIP_DIRS)
    else:
        excludes = ",".join(p for d in SKIP_DIRS for p in (f"{root}/{d}/*", f"{root}/*/{d}/*"))
    return [
        *base,
        "-f",
        "json",
        "-o",
        str(out_file),
        "-q",
        # Ignore "# nosec" comments: scanned code must not be able to switch checks off.
        "--ignore-nosec",
        "-x",
        excludes,
        "-r",
        target.arg,
    ]


def run_bandit(target: ScanTarget, settings: Settings, groups: CweGroups) -> ScannerOutcome:
    base = find_bandit()
    if base is None:
        return missing_run(TOOL, f"Bandit was not found. {INSTALL_HINT}")
    version = bandit_version()

    with neutral_dir(TOOL) as tmp:
        out_file = Path(tmp) / "bandit.json"
        try:
            res = run_command(build_command(base, target, out_file), cwd=Path(tmp), timeout_s=settings.scanner_timeout_s)
        except FileNotFoundError:
            return missing_run(TOOL, f"Bandit could not be started. {INSTALL_HINT}")
        except OSError as exc:
            return failed_run(TOOL, f"Bandit could not be started: {exc}", version)
        except ToolTimeout:
            return timeout_run(TOOL, settings.scanner_timeout_s, version)

        try:
            raw = out_file.read_text(encoding="utf-8")
        except OSError:
            raw = ""

    return parse_bandit_output(raw, res.stderr, res.returncode, target.root, groups, version, res.duration_s)


def parse_bandit_output(
    raw_json: str,
    stderr: str,
    returncode: int,
    root: Path,
    groups: CweGroups,
    version: str | None = None,
    duration_s: float = 0.0,
) -> ScannerOutcome:
    try:
        data = json.loads(raw_json) if raw_json.strip() else None
    except ValueError:
        data = None

    if not isinstance(data, dict) or "results" not in data:
        detail = last_lines(stderr) or "no output"
        return failed_run(TOOL, f"Bandit failed (exit code {returncode}): {detail}", version, duration_s)

    file_errors = [
        f"{to_rel_path(str(e.get('filename', '')), root)}: {e.get('reason', 'error')}"
        for e in data.get("errors") or []
        if isinstance(e, dict)
    ]

    reader = SourceReader(root)
    findings = [f for f in (_to_finding(r, reader, groups) for r in data.get("results") or []) if f is not None]

    message = None
    if returncode not in (0, 1):
        message = f"Bandit finished with exit code {returncode}; results may be incomplete."
    run = ToolRun(
        tool=TOOL,
        state=ToolState.OK,
        version=version,
        message=message,
        duration_s=round(duration_s, 3),
        findings_count=len(findings),
        file_errors=file_errors,
    )
    return ScannerOutcome(run, findings)


def _to_finding(r: dict, reader: SourceReader, groups: CweGroups) -> Finding | None:
    try:
        rel = to_rel_path(str(r["filename"]), reader.root)
        start = int(r["line_number"])
        test_id = str(r["test_id"])
    except (KeyError, TypeError, ValueError):
        return None
    line_range = [int(x) for x in r.get("line_range") or [] if isinstance(x, int)]
    end = max([start, *line_range])

    cwe_info = r.get("issue_cwe") or {}
    cwe = normalize_cwe(cwe_info.get("id")) if isinstance(cwe_info, dict) else normalize_cwe(cwe_info)

    issue_text = str(r.get("issue_text", "")).strip()
    title = issue_text.split(". ")[0].rstrip(".") or str(r.get("test_name", test_id))
    refs = [str(x) for x in (r.get("more_info"), cwe_info.get("link") if isinstance(cwe_info, dict) else None) if x]

    evidence = Evidence(
        rule_ids=[test_id],
        matched_code=reader.lines(rel, start, end),
        messages=[f"[bandit {test_id} {r.get('test_name', '')}] {issue_text}".replace("  ", " ")],
        references=refs,
        tool_severity={TOOL: str(r["issue_severity"])} if r.get("issue_severity") else {},
        tool_confidence={TOOL: str(r["issue_confidence"])} if r.get("issue_confidence") else {},
    )
    return Finding(
        file=rel,
        line_start=max(start, 1),
        line_end=max(end, start, 1),
        cwe=cwe,
        cwe_group=groups.group_of(cwe),
        title=title[:1].upper() + title[1:],
        detectors=[Detector.BANDIT],
        evidence=evidence,
    )
