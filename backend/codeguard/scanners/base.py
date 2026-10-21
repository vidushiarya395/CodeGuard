"""Shared helpers for running scanner tools as subprocesses.

The scanners only *read* code. They are run with a fixed argument list (never through a
shell), a timeout, and their JSON output is parsed. If a tool is missing, crashes or
times out, the caller gets a ToolRun that says so, never an exception.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from codeguard.models import Finding, ToolRun, ToolState
from codeguard.textio import read_source

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
    """What to scan: the tool is given `arg` (the absolute file or folder path) and reports paths
    that are turned back into paths relative to `root`.

    Tools never run *inside* the scanned folder: a scanned file named string.py or os.py in the
    working directory (or on sys.path) would be imported, i.e. executed, by the tool's own Python.
    Each runner starts its tool from a new, empty folder instead (see neutral_dir).
    """

    root: Path
    arg: str

    @classmethod
    def from_path(cls, path: Path) -> "ScanTarget":
        path = path.resolve()
        if path.is_file():
            return cls(root=path.parent, arg=str(path))
        return cls(root=path, arg=str(path))


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


def neutral_dir(tool: str) -> tempfile.TemporaryDirectory:
    """A new, empty folder to run a tool from, so no scanned file can shadow a module it imports."""
    return tempfile.TemporaryDirectory(prefix=f"codeguard-{tool}-", ignore_cleanup_errors=True)


def to_rel_path(path: str, root: Path) -> str:
    """A tool's path (absolute, or relative to the scan root) as a clean path relative to `root`."""
    p = Path(path)
    if p.is_absolute():
        try:
            path = p.relative_to(root).as_posix()
        except ValueError:
            # Same file, different spelling (Windows letter case, short 8.3 names): compare resolved.
            try:
                path = p.resolve().relative_to(root.resolve()).as_posix()
            except (OSError, ValueError):
                pass
    return normalize_rel_path(path)


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
                text, _ = read_source(self.root / rel_path)
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
