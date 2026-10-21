"""Taint check (detector "taint", no AI): does user input reach a dangerous call?

Inputs, sanitizers and pass-through functions come from rules/taint.yaml, the dangerous calls
(sinks) from rules/sinks.yaml. The code is read with the ast module and never run.

How it works, for each function (and for the module's own top-level code):
  1. Seed: the parameters the Code Reader marked as input (route parameters, click options).
  2. Walk the statements in order. An expression carries input ("is tainted") when it reads a
     source (request.args, input(), sys.argv ...), uses a tainted variable, or builds a value
     from one (f-strings, +, %, .format, os.path.join, name.strip() ...). Assigning a tainted
     value taints the variable; assigning a clean one cleans it.
  3. Sanitizers (int(), shlex.quote, html.escape, secure_filename ...) make the value safe for the
     CWE groups they protect against. A validation "if" (x in ALLOWED, re.fullmatch(...), x.isdigit())
     that leaves the function when it fails makes the value safe after it.
  4. A sink call (subprocess.run(cmd, shell=True), cursor.execute(sql) ...) with tainted input in a
     checked argument is reported, with the path: source line -> assignments -> sink line.
  5. One hop: a call to a helper function defined in the same file is followed once, using a
     summary of the helper (which parameters reach which sink, which ones it returns).

It is not path-sensitive (both branches of an "if" are walked one after the other) and loops
are walked once. Unknown calls do not carry input on, so the check stays quiet when it cannot tell.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, replace

from codeguard.cwe import CweGroups
from codeguard.models import Detector, Finding
from codeguard.reader import FunctionInfo, ModuleFacts, SourceMatcher
from codeguard.reader.facts import Scope, attribute_chain
from codeguard.rulechecks.loader import Rulebook, SinkRule
from codeguard.rulechecks.pyast import NameResolver, _condition_holds, file_index, name_matches
from codeguard.rulechecks.source import SourceFile, make_finding

MAX_STEPS = 8  # longest path shown in the evidence
_HTML_TAG = re.compile(r"<\s*/?\s*[a-zA-Z][^<>]*>|<\s*[a-zA-Z]+")
# Methods whose result is a bool or a number, not the text itself.
_SCALAR_METHODS = frozenset(
    "startswith endswith isdigit isdecimal isnumeric isalnum isalpha isidentifier islower isupper "
    "isspace istitle isascii count find rfind index rindex __len__".split()
)
# Builtins that return something about the value, not the value.
_NOT_CARRIED = frozenset("len isinstance issubclass hasattr callable id hash type bool any all".split())
_EXITS = frozenset({"abort", "flask.abort", "werkzeug.exceptions.abort", "sys.exit", "exit", "quit", "os._exit"})
_PARAM = "param"  # kind used for a helper's parameters while summarising it


@dataclass(frozen=True)
class Step:
    line: int
    note: str = ""


@dataclass(frozen=True)
class Taint:
    source_id: str
    kind: str  # web, cli, stdin (or "param" while summarising a helper)
    title: str
    steps: tuple[Step, ...]
    cleared: frozenset[str] = frozenset()  # CWE groups a sanitizer made this safe for
    param: int | None = None  # helper summaries: which parameter this came from
    html: bool = False  # the value was built into text holding an HTML tag

    def then(self, line: int, note: str = "") -> "Taint":
        if self.steps and self.steps[-1].line == line:
            return self
        return replace(self, steps=(*self.steps, Step(line, note)))

    def clear(self, groups: set[str]) -> "Taint":
        return replace(self, cleared=self.cleared | groups)


@dataclass
class _SinkHit:
    rule: SinkRule
    line: int
    end: int
    taint: Taint


@dataclass
class _Summary:
    """What a helper does with each parameter: which sinks it reaches and whether it is returned."""

    hits: list[_SinkHit] = field(default_factory=list)
    returns: dict[int, Taint] = field(default_factory=dict)  # parameter index -> path inside the helper
    returns_input: Taint | None = None  # the helper itself returns input (e.g. request.args["q"])


class TaintChecker:
    def __init__(self, src: SourceFile, facts: ModuleFacts, book: Rulebook, groups: CweGroups):
        self.src = src
        self.facts = facts
        self.book = book
        self.groups = groups
        self.resolver: NameResolver = file_index(src).resolver
        self.matcher = SourceMatcher(book.taint)
        self.sources = {s.id: s for s in book.taint.sources}
        self.sinks = book.taint_rules()
        self.sanitizers = [(s.call, set(s.clears)) for s in book.taint.sanitizers]
        self.propagators = list(book.taint.propagators)
        self.validator_calls = list(book.taint.validators.call)
        self.validator_re = re.compile(book.taint.validators.name_regex)
        self.helpers = {f.name: f for f in facts.functions if f.class_name is None}
        self.methods = {(f.class_name, f.name): f for f in facts.functions if f.class_name}
        self._summaries: dict[str, _Summary | None] = {}

    def run(self) -> list[Finding]:
        hits: list[_SinkHit] = []
        for fn in self.facts.functions:
            hits += _Analysis(self, fn.node, fn).run().hits
        module = ast.Module(
            body=[n for n in self.src.tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))],
            type_ignores=[],
        )
        hits += _Analysis(self, module, None).run().hits
        return self._findings(hits)

    def summary(self, fn: FunctionInfo) -> _Summary | None:
        if fn.qualname not in self._summaries:
            self._summaries[fn.qualname] = None  # guards against recursion
            a = _Analysis(self, fn.node, fn, summarise=True).run()
            s = _Summary(hits=[h for h in a.hits if h.taint.param is not None])
            for t in a.returned:
                if t.param is not None:
                    s.returns.setdefault(t.param, t)
                elif s.returns_input is None:
                    s.returns_input = t
            self._summaries[fn.qualname] = s
        return self._summaries[fn.qualname]

    def _findings(self, hits: list[_SinkHit]) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for h in sorted(hits, key=lambda h: (h.line, h.rule.id, len(h.taint.steps))):
            key = (h.rule.id, h.line)
            if key in seen:
                continue
            seen.add(key)
            path = self._path(h)
            out.append(
                make_finding(
                    h.rule,
                    self.src,
                    h.line,
                    h.end,
                    self.groups,
                    detail=f"Input: {h.taint.title} ({h.taint.kind}).",
                    extra_messages=[f"Path: {path}"],
                    detector=Detector.TAINT,
                )
            )
        return out

    def _path(self, h: _SinkHit) -> str:
        steps = list(h.taint.steps)
        if len(steps) > MAX_STEPS:
            steps = [*steps[: MAX_STEPS // 2], Step(0, "..."), *steps[-(MAX_STEPS // 2) :]]
        parts = []
        for i, st in enumerate(steps):
            if st.line == 0:
                parts.append("...")
                continue
            if i == 0:
                label = f" [input: {st.note}]" if st.note else " [input]"
            else:
                label = f" [{st.note}]" if st.note else ""
            if i == len(steps) - 1 and st.line == h.line:
                parts.append(f"line {st.line}: {self._code(st.line)}{label} [sink]")
                return " -> ".join(parts)
            parts.append(f"line {st.line}: {self._code(st.line)}{label}")
        parts.append(f"line {h.line}: {self._code(h.line)} [sink]")
        return " -> ".join(parts)

    def _code(self, line: int) -> str:
        text = self.src.lines[line - 1].strip() if 0 < line <= len(self.src.lines) else ""
        return text if len(text) <= 80 else text[:77] + "..."

    def group(self, rule: SinkRule) -> str:
        return self.groups.group_of(rule.cwe)


class _Analysis:
    """One walk over one function (or the module's top-level code)."""

    def __init__(self, checker: TaintChecker, node: ast.AST, fn: FunctionInfo | None, summarise: bool = False):
        self.c = checker
        self.node = node
        self.fn = fn
        self.summarise = summarise
        self.env: dict[str, Taint] = {}
        self.scope = Scope(node, checker.resolver)
        self.locals = self.scope.locals
        self.request_param = fn.request_param if fn else None
        self.hits: list[_SinkHit] = []
        self.returned: list[Taint] = []
        # host = urlparse(url).hostname  ->  derived["host"] = {"url"}: validating host validates url
        self.derived: dict[str, set[str]] = {}

    # --- driver ---

    def run(self) -> "_Analysis":
        fn = self.fn
        if fn is not None:
            if self.summarise:
                params = [p for p in fn.params if p not in ("self", "cls")]
                for i, p in enumerate(params):
                    self.env[p] = Taint(_PARAM, _PARAM, "parameter", (Step(fn.line, f"parameter {p}"),), param=i)
            else:
                for p, sid in fn.input_params.items():
                    src = self.c.sources.get(sid)
                    if src is not None and src.taint:
                        self.env[p] = Taint(src.id, src.kind, src.title, (Step(fn.line, f"parameter {p}"),))
        body = self.node.body if isinstance(self.node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)) else []
        self.block(body)
        return self

    def block(self, stmts: list[ast.stmt]) -> None:
        for s in stmts:
            self.stmt(s)

    def stmt(self, s: ast.stmt) -> None:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(s, ast.Assign):
            t = self.expr(s.value)
            for target in s.targets:
                self.bind(target, t, s.lineno)
                if isinstance(target, ast.Name):
                    self.derived[target.id] = _names_in(s.value) & set(self.env)
        elif isinstance(s, ast.AnnAssign):
            if s.value is not None:
                self.bind(s.target, self.expr(s.value), s.lineno)
        elif isinstance(s, ast.AugAssign):
            t = self.expr(s.value)
            if isinstance(s.target, ast.Name):
                old = self.env.get(s.target.id)
                new = old or t
                if new is not None:
                    self.env[s.target.id] = new.then(s.lineno)
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            self.bind(s.target, self.expr(s.iter), s.lineno)
            self.block(s.body)
            self.block(s.orelse)
        elif isinstance(s, ast.While):
            self.expr(s.test)
            self.block(s.body)
            self.block(s.orelse)
        elif isinstance(s, ast.If):
            self.if_(s)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                t = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, t, s.lineno)
            self.block(s.body)
        elif isinstance(s, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            self.block(s.body)
            for h in s.handlers:
                self.block(h.body)
            self.block(s.orelse)
            self.block(s.finalbody)
        elif isinstance(s, ast.Return):
            if s.value is not None:
                t = self.expr(s.value)
                if t is not None:
                    self.returned.append(t.then(s.lineno, "returned"))
                    self.flask_return(s, t)
        elif isinstance(s, ast.Match):
            self.expr(s.subject)
            for case in s.cases:
                self.block(case.body)
        else:
            for child in ast.iter_child_nodes(s):
                if isinstance(child, ast.expr):
                    self.expr(child)

    def bind(self, target: ast.AST, t: Taint | None, line: int) -> None:
        if isinstance(target, ast.Name):
            if t is None:
                self.env.pop(target.id, None)
            else:
                self.env[target.id] = t.then(line)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.bind(elt, t, line)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, t, line)
        else:
            # obj.attr = ... / d[key] = ...: the expressions inside may hold sinks
            for child in ast.iter_child_nodes(target):
                if isinstance(child, ast.expr):
                    self.expr(child)

    # --- validation guards ---

    def if_(self, s: ast.If) -> None:
        self.expr(s.test)
        positive, negative = self.guarded(s.test)
        positive = {m for n in positive for m in (n, *self.derived.get(n, ())) if m in self.env}
        negative = {m for n in negative for m in (n, *self.derived.get(n, ())) if m in self.env}
        saved = {n: self.env.pop(n) for n in positive}
        self.block(s.body)
        for n, t in saved.items():
            self.env.setdefault(n, t)  # outside the checked branch the value is not validated
        self.block(s.orelse)
        if negative and _exits(s.body, self.c.resolver) and not s.orelse:
            for n in negative:
                self.env.pop(n, None)

    def guarded(self, test: ast.expr) -> tuple[set[str], set[str]]:
        """Names a test validates when it is true (positive) or when it is false (negative)."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            pos, neg = self.guarded(test.operand)
            return neg, pos
        if isinstance(test, ast.BoolOp):
            parts = [self.guarded(v) for v in test.values]
            if isinstance(test.op, ast.And):
                return set().union(*(p for p, _ in parts)), set()
            return set(), set().union(*(n for _, n in parts))
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            names = _names_in(test.left)
            if _is_fixed(test.comparators[0]):
                op = test.ops[0]
                if isinstance(op, (ast.In, ast.Eq, ast.Is)):
                    return names, set()
                if isinstance(op, (ast.NotIn, ast.NotEq, ast.IsNot)):
                    return set(), names
            return set(), set()
        if isinstance(test, ast.Call):
            name = self.qname(test.func) or ""
            last = test.func.attr if isinstance(test.func, ast.Attribute) else (test.func.id if isinstance(test.func, ast.Name) else "")
            if name_matches(name, self.c.validator_calls) or self.c.validator_re.match(last or ""):
                names: set[str] = set()
                for a in [*test.args, *(k.value for k in test.keywords)]:
                    names |= _names_in(a)
                if isinstance(test.func, ast.Attribute):
                    names |= _names_in(test.func.value)
                return names, set()
        return set(), set()

    # --- expressions ---

    def qname(self, node: ast.AST) -> str | None:
        return self.scope.qname(node)

    def source(self, node: ast.AST) -> Taint | None:
        target = node.func if isinstance(node, ast.Call) else node
        root, attrs = attribute_chain(target)
        src = None
        if self.request_param and root == self.request_param:
            src = self.c.matcher.by_request_param(attrs)
        elif isinstance(target, (ast.Name, ast.Attribute)):
            src = self.c.matcher.by_name(self.qname(target))
        if src is None or not src.taint:
            return None
        return Taint(src.id, src.kind, src.title, (Step(node.lineno),))

    def expr(self, node: ast.AST | None) -> Taint | None:
        if node is None:
            return None
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, ast.Name):
            return self.env.get(node.id) or (None if node.id in self.locals else self.source(node))
        if isinstance(node, ast.Attribute):
            return self.expr(node.value) or self.source(node)
        if isinstance(node, ast.Subscript):
            self.expr(node.slice)
            return self.expr(node.value)
        if isinstance(node, ast.JoinedStr):
            return _with_html(_first([self.expr(v) for v in node.values]), node)
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value)
        if isinstance(node, ast.BinOp):
            return _with_html(_first([self.expr(node.left), self.expr(node.right)]), node)
        if isinstance(node, ast.BoolOp):
            return _first([self.expr(v) for v in node.values])
        if isinstance(node, ast.IfExp):
            self.expr(node.test)
            return _first([self.expr(node.body), self.expr(node.orelse)])
        if isinstance(node, ast.Compare):
            for n in [node.left, *node.comparators]:
                self.expr(n)
            return None
        if isinstance(node, ast.UnaryOp):
            t = self.expr(node.operand)
            return None if isinstance(node.op, ast.Not) else t
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _first([self.expr(e) for e in node.elts])
        if isinstance(node, ast.Dict):
            return _first([self.expr(k) for k in node.keys if k is not None] + [self.expr(v) for v in node.values])
        if isinstance(node, (ast.Await, ast.Starred, ast.YieldFrom)):
            return self.expr(node.value)
        if isinstance(node, ast.Yield):
            return self.expr(node.value)
        if isinstance(node, ast.NamedExpr):
            t = self.expr(node.value)
            self.bind(node.target, t, node.lineno)
            return t
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            it = None
            for gen in node.generators:
                gt = self.expr(gen.iter)
                self.bind(gen.target, gt, node.lineno)
                it = it or gt
                for cond in gen.ifs:
                    self.expr(cond)
            elts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            return _first([self.expr(e) for e in elts]) or it
        if isinstance(node, ast.Slice):
            for n in (node.lower, node.upper, node.step):
                self.expr(n)
        return None

    def call(self, node: ast.Call) -> Taint | None:
        func = node.func
        recv = self.expr(func.value) if isinstance(func, ast.Attribute) else None
        arg_ts = [self.expr(a) for a in node.args]
        kw_ts = {kw.arg: self.expr(kw.value) for kw in node.keywords}
        name = self.qname(func)

        src = self.source(node)
        if src is not None:
            return src
        self.check_sinks(node, name, arg_ts, kw_ts)
        helper = self.helper_result(node, arg_ts, kw_ts)
        if helper is not False:
            return helper  # type: ignore[return-value]

        values = [*arg_ts, *kw_ts.values()]
        if name:
            for calls, clears in self.c.sanitizers:
                if name_matches(name, calls):
                    t = _first([*values, recv])
                    if t is None or "all" in clears:
                        return None
                    return t.clear(clears).then(node.lineno, f"made safe for {', '.join(sorted(clears))}")
            if name in _NOT_CARRIED:
                return None
            if name_matches(name, self.c.propagators):
                return _first([*values, recv])
        if isinstance(func, ast.Attribute):
            if func.attr in _SCALAR_METHODS:
                return None
            if recv is not None:
                return recv
            if isinstance(func.value, (ast.Constant, ast.JoinedStr)):  # "sep".join(x), "{}".format(x)
                return _with_html(_first(values), func.value)
        return None

    def check_sinks(self, node: ast.Call, name: str | None, arg_ts: list, kw_ts: dict) -> None:
        text = name or _text_name(node.func)
        if not text:
            return
        for rule in self.c.sinks:
            for pat in rule.patterns:
                calls = pat.call if name else [p for p in pat.call if p.startswith("*.")]
                if not name_matches(text, calls):
                    continue
                if not all(_condition_holds(node, cond, self.c.resolver) for cond in pat.where):
                    continue
                checked: list[tuple[Taint | None, ast.AST]] = []
                for pos in pat.args:
                    if pos < len(node.args) and not any(isinstance(a, ast.Starred) for a in node.args[: pos + 1]):
                        checked.append((arg_ts[pos], node.args[pos]))
                for kw in node.keywords:
                    if kw.arg in pat.kwargs:
                        checked.append((kw_ts.get(kw.arg), kw.value))
                for t, arg in checked:
                    self.report(rule, node, t, arg)
                break

    def report(self, rule: SinkRule, node: ast.AST, t: Taint | None, arg: ast.AST) -> None:
        if t is None:
            return
        if t.kind != _PARAM and t.kind not in rule.from_:
            return
        if self.c.group(rule) in t.cleared:
            return
        if rule.html_only and not (t.html or _has_html(arg)):
            return
        self.hits.append(_SinkHit(rule, node.lineno, node.end_lineno or node.lineno, t))

    def flask_return(self, s: ast.Return, t: Taint) -> None:
        if self.summarise or self.fn is None or self.fn.framework != "flask":
            return
        for rule in self.c.sinks:
            if rule.flask_return:
                self.report(rule, s, t, s.value)

    # --- one hop into helpers ---

    def helper_result(self, node: ast.Call, arg_ts: list, kw_ts: dict):
        """Follow a call to a function defined in this file. Returns False when it is not one."""
        if self.summarise:
            return False
        func = node.func
        fn = None
        if isinstance(func, ast.Name) and func.id not in self.locals:
            fn = self.c.helpers.get(func.id)
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in ("self", "cls")
            and self.fn is not None
        ):
            fn = self.c.methods.get((self.fn.class_name, func.attr))
        if fn is None or fn.node is self.node:
            return False
        summary = self.c.summary(fn)
        if summary is None:
            return False
        params = [p for p in fn.params if p not in ("self", "cls")]

        def arg_taint(i: int) -> Taint | None:
            if i < len(node.args) and not any(isinstance(a, ast.Starred) for a in node.args[: i + 1]):
                return arg_ts[i]
            return kw_ts.get(params[i]) if i < len(params) else None

        call_note = f"passed to {fn.name}()"
        for h in summary.hits:
            outer = arg_taint(h.taint.param)  # type: ignore[arg-type]
            if outer is None or outer.kind not in h.rule.from_:
                continue
            group = self.c.group(h.rule)
            if group in outer.cleared or group in h.taint.cleared:
                continue
            inner = h.taint.steps[1:]  # the first inner step is the parameter itself
            t = outer.then(node.lineno, call_note)
            t = replace(t, steps=(*t.steps, Step(fn.line, f"in {fn.name}()"), *inner), cleared=t.cleared | h.taint.cleared)
            self.hits.append(_SinkHit(h.rule, h.line, h.end, t))
        result = summary.returns_input.then(node.lineno, f"returned by {fn.name}()") if summary.returns_input else None
        for i, inner in summary.returns.items():
            outer = arg_taint(i)
            if outer is not None:
                result = result or outer.clear(set(inner.cleared)).then(node.lineno, f"returned by {fn.name}()")
        return result


# --- helpers ---


def _first(items) -> Taint | None:
    for t in items:
        if t is not None:
            return t
    return None


def _names_in(node: ast.AST) -> set[str]:
    """Every variable read in an expression (urlparse(url).hostname -> {"urlparse", "url"})."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_fixed(node: ast.AST) -> bool:
    """A constant, a collection of constants, or an ALL_CAPS module constant (ALLOWED_HOSTS)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(isinstance(e, ast.Constant) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(isinstance(k, ast.Constant) for k in node.keys)
    if isinstance(node, ast.Name):
        return node.id.isupper() or node.id.lstrip("_").isupper()
    if isinstance(node, ast.Attribute):
        return node.attr.isupper()
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "keys":
        return _is_fixed(node.func.value)
    return False


def _exits(body: list[ast.stmt], resolver: NameResolver) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        return (resolver.resolve(last.value.func) or "") in _EXITS
    return False


def _text_name(func: ast.AST) -> str | None:
    """db.execute -> "db.execute" when the receiver is a local variable whose type is unknown."""
    try:
        text = ast.unparse(func)
    except Exception:
        return None
    return text if re.fullmatch(r"[A-Za-z_][\w.]*", text) and "." in text else None


def _has_html(node: ast.AST) -> bool:
    """The expression holds an HTML tag in one of its string constants."""
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and _HTML_TAG.search(n.value):
            return True
    return False


def _with_html(t: Taint | None, node: ast.AST) -> Taint | None:
    if t is not None and not t.html and _has_html(node):
        return replace(t, html=True)
    return t


def check_taint(src: SourceFile, facts: ModuleFacts, book: Rulebook, groups: CweGroups) -> list[Finding]:
    if src.tree is None or not facts.parsed:
        return []
    return TaintChecker(src, facts, book, groups).run()
