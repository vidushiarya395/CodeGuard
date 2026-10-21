"""Code Reader: facts about the scanned code, read with Python's ast module (never run).

    read_project(sources, taint) -> ProjectFacts   every file's functions, routes, decorators and inputs
"""

from __future__ import annotations

from dataclasses import dataclass, field

from codeguard.reader.facts import (
    ClassInfo,
    EntryPoint,
    FunctionInfo,
    ImportInfo,
    ModuleFacts,
    Route,
    SourceMatcher,
    attach_project_urls,
    read_module,
)
from codeguard.rulechecks.loader import TaintFile
from codeguard.rulechecks.source import SourceSet

__all__ = [
    "ClassInfo",
    "EntryPoint",
    "FunctionInfo",
    "ImportInfo",
    "ModuleFacts",
    "ProjectFacts",
    "Route",
    "SourceMatcher",
    "read_module",
    "read_project",
]


@dataclass
class ProjectFacts:
    modules: dict[str, ModuleFacts] = field(default_factory=dict)  # by file (relative path)
    errors: list[str] = field(default_factory=list)

    def get(self, rel: str) -> ModuleFacts | None:
        return self.modules.get(rel)


def read_project(sources: SourceSet, taint: TaintFile) -> ProjectFacts:
    """Read every Python file. A file that cannot be read becomes an error message, never a crash."""
    out = ProjectFacts()
    for src in sources.python:
        try:
            out.modules[src.rel] = read_module(src, taint)
        except (RecursionError, MemoryError):
            out.modules[src.rel] = ModuleFacts(file=src.rel, parsed=False)
            out.errors.append(f"{src.rel}: too deeply nested to analyse; skipped by the Code Reader")
        except Exception as exc:  # a bug in the reader must not stop the scan
            out.modules[src.rel] = ModuleFacts(file=src.rel, parsed=False)
            out.errors.append(f"{src.rel}: Code Reader failed ({type(exc).__name__}: {exc})")
    attach_project_urls(list(out.modules.values()))
    return out
