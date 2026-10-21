"""Splits a file into review units for the AI review.

A small file is one unit. A bigger file is split by top-level function and class (a big class by
method), and consecutive small definitions are packed together up to the line budget. Every unit
of a split file also carries the file's imports and module-level assignments as shared context,
so the model knows what `app`, `db` or `UPLOAD_DIR` are. Line numbers stay the file's real ones.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from codeguard.reader.facts import FunctionInfo, ModuleFacts
from codeguard.rulechecks.source import SourceFile

MAX_CONTEXT_LINES = 60  # imports and constants shown with every unit of a split file
MAX_CONTEXT_STMT_LINES = 3  # longer module-level assignments are not repeated as context


@dataclass
class ReviewUnit:
    file: str
    name: str  # "whole file", "function create_post", "class PostView", "functions a, b", "module code"
    body: list[tuple[int, int]]  # the unit's own line ranges (inclusive)
    context: list[int] = field(default_factory=list)  # shared context lines (imports, constants)
    functions: list[FunctionInfo] = field(default_factory=list)  # functions inside the unit
    truncated: tuple[int, int] | None = None  # lines of an over-long definition that were left out

    @property
    def whole_file(self) -> bool:
        return self.name == "whole file"

    @property
    def body_lines(self) -> list[int]:
        return [n for a, b in self.body for n in range(a, b + 1)]

    @property
    def shown_lines(self) -> list[int]:
        return sorted(set(self.context) | set(self.body_lines))

    @property
    def label(self) -> str:
        return self.file if self.whole_file else f"{self.file} ({self.name})"


@dataclass
class _Block:
    name: str
    start: int
    end: int
    functions: list[FunctionInfo]

    @property
    def size(self) -> int:
        return self.end - self.start + 1


def split_units(src: SourceFile, facts: ModuleFacts | None, max_lines: int = 150, max_unit_lines: int = 400) -> list[ReviewUnit]:
    n = len(src.lines)
    functions = facts.functions if facts else []
    if n <= max_lines or src.tree is None:
        unit = ReviewUnit(src.rel, "whole file", [(1, n)] if n else [], functions=list(functions))
        if n > max_unit_lines:  # a big file that does not parse cannot be split by function
            unit.body = [(1, max_unit_lines)]
            unit.truncated = (max_unit_lines + 1, n)
        return [unit]

    context = _context_lines(src.tree)
    blocks = _blocks(src.tree, functions, max_lines)
    units: list[ReviewUnit] = []
    current: list[_Block] = []

    def flush() -> None:
        if not current:
            return
        units.append(
            ReviewUnit(
                src.rel,
                _name(current),
                [(b.start, b.end) for b in current],
                context=[c for c in context if not any(b.start <= c <= b.end for b in current)],
                functions=[f for b in current for f in b.functions],
            )
        )
        current.clear()

    for block in blocks:
        if block.size > max_lines:
            flush()
            unit = ReviewUnit(src.rel, block.name, [(block.start, block.end)], context=list(context), functions=block.functions)
            if block.size > max_unit_lines:
                cut = block.start + max_unit_lines - 1
                unit.body = [(block.start, cut)]
                unit.truncated = (cut + 1, block.end)
            units.append(unit)
            continue
        if current and sum(b.size for b in current) + block.size > max_lines:
            flush()
        current.append(block)
    flush()
    return units


def _context_lines(tree: ast.Module) -> list[int]:
    lines: list[int] = []
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign)):
            end = stmt.end_lineno or stmt.lineno
            if end - stmt.lineno + 1 <= MAX_CONTEXT_STMT_LINES:
                lines.extend(range(stmt.lineno, end + 1))
        if len(lines) >= MAX_CONTEXT_LINES:
            break
    return lines[:MAX_CONTEXT_LINES]


def _start(node: ast.AST) -> int:
    decorators = getattr(node, "decorator_list", [])
    return min([node.lineno, *(d.lineno for d in decorators)])


def _blocks(tree: ast.Module, functions: list[FunctionInfo], max_lines: int) -> list[_Block]:
    """Top-level definitions (big classes split by method) and runs of other module-level code."""
    by_node = {id(f.node): f for f in functions}
    blocks: list[_Block] = []
    loose: list[ast.stmt] = []

    def flush_loose() -> None:
        code = [s for s in loose if not isinstance(s, (ast.Import, ast.ImportFrom))]
        if code:
            blocks.append(_Block("module code", code[0].lineno, max(s.end_lineno or s.lineno for s in code), []))
        loose.clear()

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            flush_loose()
            fn = by_node.get(id(stmt))
            blocks.append(_Block(f"function {stmt.name}", _start(stmt), stmt.end_lineno or stmt.lineno, [fn] if fn else []))
        elif isinstance(stmt, ast.ClassDef):
            flush_loose()
            start, end = _start(stmt), stmt.end_lineno or stmt.lineno
            methods = [s for s in stmt.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if end - start + 1 > max_lines and methods:
                head_end = _start(methods[0]) - 1
                blocks.append(_Block(f"class {stmt.name}", start, max(head_end, stmt.lineno), []))
                for m in methods:
                    fn = by_node.get(id(m))
                    blocks.append(_Block(f"method {stmt.name}.{m.name}", _start(m), m.end_lineno or m.lineno, [fn] if fn else []))
            else:
                members = [by_node[id(m)] for m in methods if id(m) in by_node]
                blocks.append(_Block(f"class {stmt.name}", start, end, members))
        else:
            loose.append(stmt)
    flush_loose()
    return blocks


def _name(blocks: list[_Block]) -> str:
    if len(blocks) == 1:
        return blocks[0].name
    names = [b.name.split(" ", 1)[-1] for b in blocks if b.name != "module code"]
    prefix = "module code and " if len(names) < len(blocks) else ""
    shown = ", ".join(names[:4]) + (" ..." if len(names) > 4 else "")
    return f"{prefix}definitions {shown}"
