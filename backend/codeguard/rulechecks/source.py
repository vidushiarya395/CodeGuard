"""Finds and reads the files the rule checks look at. Files are only read and parsed, never run."""

from __future__ import annotations

import ast
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codeguard.cwe import CweGroups
from codeguard.models import Detector, Evidence, Finding
from codeguard.rulechecks.loader import RuleMeta
from codeguard.scanners.base import MAX_EVIDENCE_LINES, SKIP_DIRS

MAX_FILE_BYTES = 2_000_000


@dataclass
class SourceFile:
    rel: str  # path relative to the scan root, with forward slashes (same as Agent 1)
    text: str
    tree: ast.Module | None = None  # None for requirements files and files that do not parse
    lines: list[str] = field(default_factory=list)
    # Parsed-tree index shared by the AST rule checks (built on first use; see pyast.file_index).
    ast_index: Any = field(default=None, repr=False, compare=False)

    def snippet(self, start: int, end: int) -> str | None:
        end = min(max(end, start), start + MAX_EVIDENCE_LINES - 1)
        chunk = self.lines[start - 1 : end]
        return "\n".join(chunk) if chunk else None


@dataclass
class SourceSet:
    python: list[SourceFile] = field(default_factory=list)
    requirements: list[SourceFile] = field(default_factory=list)
    # Top-level names that belong to the scanned project itself (its own modules and packages).
    local_modules: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)


def is_requirements_file(rel: str) -> bool:
    parts = rel.lower().split("/")
    name = parts[-1]
    if not name.endswith(".txt"):
        return False
    return name.startswith("requirements") or (len(parts) > 1 and parts[-2] == "requirements")


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            yield Path(dirpath) / name


def load_sources(path: Path, display_name: str | None = None) -> SourceSet:
    """Read the files under `path`. For a single file, `display_name` replaces its on-disk name
    (pasted code is saved under a random name; rules and reports use the name the user gave)."""
    path = Path(path).resolve()
    if path.is_file():
        root, files = path.parent, [path]
    else:
        root, files = path, list(_iter_files(path))

    out = SourceSet()
    for file in files:
        rel = display_name if display_name and path.is_file() else file.relative_to(root).as_posix()
        is_py = file.suffix == ".py"
        if not is_py and not is_requirements_file(rel):
            continue
        if file.is_symlink():
            out.errors.append(f"{rel}: skipped (symbolic link)")
            continue
        try:
            if file.stat().st_size > MAX_FILE_BYTES:
                out.errors.append(f"{rel}: skipped (larger than {MAX_FILE_BYTES // 1_000_000} MB)")
                continue
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            out.errors.append(f"{rel}: could not be read ({exc.strerror or exc})")
            continue

        src = SourceFile(rel=rel, text=text, lines=text.splitlines())
        if is_py:
            src.tree = parse_python(text, rel, out.errors)
            out.python.append(src)
            parts = rel[: -len(".py")].split("/")
            out.local_modules.update(p for p in parts if p and p != "__init__")
        else:
            out.requirements.append(src)
    return out


def parse_python(text: str, rel: str, errors: list[str]) -> ast.Module | None:
    """Parse with ast (this never runs the code). Returns None if the file is not valid Python."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # e.g. SyntaxWarning for invalid escape sequences
            return ast.parse(text, filename=rel)
    except (SyntaxError, ValueError) as exc:
        line = getattr(exc, "lineno", None)
        errors.append(f"{rel}: not valid Python{f' (line {line})' if line else ''}; only text checks were run")
        return None


def make_finding(
    rule: RuleMeta,
    src: SourceFile,
    line_start: int,
    line_end: int,
    groups: CweGroups,
    *,
    title: str | None = None,
    detail: str | None = None,
    matched_code: str | None = None,
    extra_refs: list[str] | None = None,
    extra_messages: list[str] | None = None,
) -> Finding:
    line_start = max(line_start, 1)
    line_end = max(line_end, line_start)
    message = f"[rule {rule.id}] {detail + ' ' if detail else ''}{rule.message}"
    evidence = Evidence(
        rule_ids=[rule.id],
        matched_code=matched_code if matched_code is not None else src.snippet(line_start, line_end),
        messages=[message, *(extra_messages or []), f"How to fix: {rule.fix_hint}"],
        references=list(dict.fromkeys([*rule.sources, *(extra_refs or [])])),
    )
    return Finding(
        file=src.rel,
        line_start=line_start,
        line_end=line_end,
        cwe=rule.cwe,
        cwe_group=groups.group_of(rule.cwe),
        title=title or rule.title,
        detectors=[Detector.RULE_CHECK],
        evidence=evidence,
    )


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per rule, file and start line."""
    seen: set[tuple] = set()
    out = []
    for f in findings:
        key = (f.file, f.line_start, tuple(f.evidence.rule_ids), f.title)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
