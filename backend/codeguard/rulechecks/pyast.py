"""AST pattern matcher for deprecated_apis.yaml and insecure_settings.yaml.

The code is parsed with Python's ast module and never run. Every name is turned into a full
dotted name before it is compared with the rules:

    import yaml as y; y.load(...)            ->  yaml.load
    from flask import Flask; app = Flask()   ->  app.run(...) is flask.Flask().run
    with tarfile.open(p) as tar: tar.extractall()  ->  tarfile.open().extractall

Variables are tracked per file, without following control flow. That is enough for the
straightforward code these rules look for, and keeps every match easy to explain.
"""

from __future__ import annotations

import ast
import re
from functools import lru_cache
from typing import Any

from codeguard.cwe import CweGroups
from codeguard.models import Finding
from codeguard.rulechecks.loader import AstRule, Condition, Pattern
from codeguard.rulechecks.source import SourceFile, make_finding


class NameResolver:
    def __init__(self, tree: ast.Module, nodes: list[ast.AST] | None = None):
        nodes = nodes if nodes is not None else list(ast.walk(tree))
        self.aliases: dict[str, str] = {}
        self.bindings: dict[str, str] = {}
        self._memo: dict[int, tuple[ast.AST, str | None]] | None = None  # used once the bindings are final
        for node in nodes:
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.aliases[top] = top
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for a in node.names:
                    if a.name != "*":
                        self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        # Two passes so that chains like  s = requests.Session(); r = s.get(...)  resolve.
        candidates = [b for node in nodes for b in _simple_bindings(node)]
        for _ in range(2):
            for name, value in candidates:
                resolved = self.resolve(value)
                if resolved:
                    self.bindings[name] = resolved
        self._memo = {}

    def resolve(self, node: ast.AST | None) -> str | None:
        if self._memo is None or node is None:
            return self._resolve(node)
        # The node is stored with its result: ids of freed nodes can be reused, so check identity.
        entry = self._memo.get(id(node))
        if entry is None or entry[0] is not node:
            entry = (node, self._resolve(node))
            self._memo[id(node)] = entry
        return entry[1]

    def _resolve(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.bindings:
                return self.bindings[node.id]
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            base = self.resolve(node.func)
            return f"{base}()" if base else None
        return None

    def target_name(self, node: ast.AST) -> str | None:
        """Name of an assignment target: DEBUG, flask.Flask().debug, flask.Flask().config[DEBUG]."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Subscript):
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                base = self.resolve(node.value)
                return f"{base}[{key.value}]" if base else None
        return None


def _simple_bindings(node: ast.AST):
    """Yield (variable, value) for  x = call(...)  and  with call(...) as x."""
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
        for t in node.targets:
            if isinstance(t, ast.Name):
                yield t.id, node.value
    elif isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Call) and isinstance(node.target, ast.Name):
        yield node.target.id, node.value
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and isinstance(item.optional_vars, ast.Name):
                yield item.optional_vars.id, item.context_expr


@lru_cache(maxsize=1024)
def _glob(pattern: str) -> re.Pattern[str]:
    # Only "*" is special; brackets in config keys like config[DEBUG] are literal.
    return re.compile("^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$")


def name_matches(name: str | None, patterns: list[str]) -> bool:
    return name is not None and any(_glob(p).match(name) for p in patterns)


_MISSING = object()


def _get_arg(call: ast.Call, cond: Condition) -> Any:
    """The argument node, _MISSING if it is surely not given, or None if we cannot tell."""
    if cond.arg is not None:
        for kw in call.keywords:
            if kw.arg == cond.arg:
                return kw.value
    if cond.position is not None:
        for i, a in enumerate(call.args):
            if isinstance(a, ast.Starred):
                return None  # *args: positions after this are unknown
            if i == cond.position:
                return a
    if any(kw.arg is None for kw in call.keywords):
        return None  # **kwargs may contain it
    if any(isinstance(a, ast.Starred) for a in call.args):
        return None
    return _MISSING


def _is_constant(node: ast.AST, expected: Any) -> bool:
    return (
        isinstance(node, ast.Constant)
        and type(node.value) is type(expected)  # True must not match 1
        and node.value == expected
    )


def _condition_holds(call: ast.Call, cond: Condition, resolver: NameResolver) -> bool:
    node = _get_arg(call, cond)
    if node is None:
        return False  # unknown: do not report what we cannot show
    if cond.missing:
        return node is _MISSING
    if cond.missing_or_not_in is not None:
        return node is _MISSING or resolver.resolve(node) not in cond.missing_or_not_in
    if node is _MISSING:
        return False
    if cond.has_is:
        return _is_constant(node, cond.is_)
    if cond.in_ is not None:
        return resolver.resolve(node) in cond.in_
    if cond.not_constant:
        return not isinstance(node, ast.Constant)
    if cond.dict_has is not None:
        if not isinstance(node, ast.Dict):
            return False
        entries = {
            k.value: v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        return all(key in entries and _is_constant(entries[key], val) for key, val in cond.dict_has.items())
    return False


def _value_matches(value: ast.AST, pattern: Pattern, resolver: NameResolver) -> bool:
    if pattern.has_value_is:
        return _is_constant(value, pattern.value_is)
    return resolver.resolve(value) in (pattern.value_in or [])


def _assignments(node: ast.AST):
    if isinstance(node, ast.Assign):
        for t in node.targets:
            yield t, node.value
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        yield node.target, node.value


class FileIndex:
    """One walk over a file's tree: its nodes grouped by kind, plus the name resolver.

    Built once per file and shared by every rule, instead of walking the tree once per pattern.
    """

    def __init__(self, tree: ast.Module):
        nodes = list(ast.walk(tree))
        self.resolver = NameResolver(tree, nodes)
        self.calls = [n for n in nodes if isinstance(n, ast.Call)]
        self.loads = [n for n in nodes if isinstance(n, (ast.Attribute, ast.Name)) and isinstance(n.ctx, ast.Load)]
        self.imports = [n for n in nodes if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assigns = [n for n in nodes if isinstance(n, (ast.Assign, ast.AnnAssign))]


def _pattern_hits(index: FileIndex, pattern: Pattern) -> list[ast.AST]:
    resolver = index.resolver
    hits: list[ast.AST] = []
    kind = pattern.kind
    if kind == "call":
        for node in index.calls:
            if name_matches(resolver.resolve(node.func), pattern.call) and all(
                _condition_holds(node, c, resolver) for c in pattern.where
            ):
                hits.append(node)
    elif kind == "attribute":
        hits = [n for n in index.loads if name_matches(resolver.resolve(n), pattern.attribute)]
    elif kind == "import_":
        for node in index.imports:
            if isinstance(node, ast.Import):
                if any(_module_matches(a.name, pattern.import_) for a in node.names):
                    hits.append(node)
            elif node.level == 0 and node.module and _module_matches(node.module, pattern.import_):
                hits.append(node)
    elif kind == "assign":
        for node in index.assigns:
            for target, value in _assignments(node):
                if name_matches(resolver.target_name(target), pattern.assign) and _value_matches(
                    value, pattern, resolver
                ):
                    hits.append(node)
    return hits


def _module_matches(module: str, patterns: list[str]) -> bool:
    return any(module == p or module.startswith(p + ".") for p in patterns)


def file_index(src: SourceFile) -> FileIndex:
    if src.ast_index is None:
        src.ast_index = FileIndex(src.tree)
    return src.ast_index


def check_ast_rules(src: SourceFile, rules: list[AstRule], groups: CweGroups) -> list[Finding]:
    if src.tree is None:
        return []
    index = file_index(src)
    findings: list[Finding] = []
    for rule in rules:
        seen_lines: set[int] = set()
        for pattern in rule.patterns:
            if pattern.files and not name_matches(src.rel, pattern.files):
                continue
            for node in _pattern_hits(index, pattern):
                start = node.lineno
                if start in seen_lines:
                    continue
                seen_lines.add(start)
                findings.append(make_finding(rule, src, start, node.end_lineno or start, groups))
    return findings
