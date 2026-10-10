"""Shared helpers for running scanner tools as subprocesses.

The scanners only *read* code. They are run with a fixed argument list (never through a
shell), a timeout, and their JSON output is parsed. If a tool is missing, crashes or
times out, the caller gets a ToolRun that says so, never an exception.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from codeguard.models import Finding, ToolRun, ToolState

# Folders that hold installed or vendored code, not the user's own code.
SKIP_DIRS: tuple[str, ...] = (
    ".git",
    ".venv",
    ".venv-semgrep",
    "venv",
    ".tox",
    ".nox",
    "node_modules",
    "site-packages",
    "vendor",
    "third_party",
    "__pycache__",
)

MAX_EVIDENCE_LINES = 20


@dataclass
class ScanTarget:
    """What to scan: the tool runs inside `cwd` and is given `arg` (a file name or ".")."""

    cwd: Path
    arg: str

    @classmethod
    def from_path(cls, path: Path) -> "ScanTarget":
        path = path.resolve()
        if path.is_file():
            return cls(cwd=path.parent, arg=path.name)
        return cls(cwd=path, arg=".")


@dataclass
class ScannerOutcome:
    run: ToolRun
    findings: list[Finding] = field(default_factory=list)


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    duration_s: float


class ToolTimeout(Exception):
    pass


def run_command(cmd: list[str], cwd: Path, timeout_s: int) -> CommandResult:
    """Run a tool without a shell. Raises FileNotFoundError or ToolTimeout."""
    env = dict(os.environ)
    # Semgrep and Bandit are Python programs; force UTF-8 so Windows code pages don't break them.
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeout(f"timed out after {timeout_s} s") from exc
    return CommandResult(proc.returncode, proc.stdout or "", proc.stderr or "", time.perf_counter() - start)


def normalize_rel_path(path: str) -> str:
    """Turn a tool's path into a clean relative path with forward slashes."""
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


class SourceReader:
    """Reads the flagged lines from disk so every finding carries the real code as evidence."""

    def __init__(self, root: Path):
        self.root = root
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, rel_path: str, start: int, end: int) -> str | None:
        if rel_path not in self._cache:
            try:
                text = (self.root / rel_path).read_text(encoding="utf-8", errors="replace")
                self._cache[rel_path] = text.splitlines()
            except OSError:
                self._cache[rel_path] = None
        all_lines = self._cache[rel_path]
        if not all_lines or start < 1:
            return None
        end = min(end, start + MAX_EVIDENCE_LINES - 1)
        chunk = all_lines[start - 1 : end]
        return "\n".join(chunk) if chunk else None


def last_lines(text: str, n: int = 3) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return " | ".join(lines[-n:])


def missing_run(tool: str, message: str) -> ScannerOutcome:
    return ScannerOutcome(ToolRun(tool=tool, state=ToolState.MISSING, message=message))


def failed_run(tool: str, message: str, version: str | None = None, duration_s: float = 0.0) -> ScannerOutcome:
    return ScannerOutcome(
        ToolRun(tool=tool, state=ToolState.FAILED, message=message, version=version, duration_s=duration_s)
    )


def timeout_run(tool: str, timeout_s: int, version: str | None = None) -> ScannerOutcome:
    return ScannerOutcome(
        ToolRun(
            tool=tool,
            state=ToolState.TIMEOUT,
            message=f"{tool} did not finish within {timeout_s} s and was stopped. "
            "Try a smaller target or raise CODEGUARD_SCANNER_TIMEOUT.",
            version=version,
            duration_s=float(timeout_s),
        )
    )


def humanize(rule_name: str) -> str:
    words = rule_name.replace("_", " ").replace("-", " ").split()
    if not words:
        return rule_name
    text = " ".join(words)
    return text[0].upper() + text[1:]
