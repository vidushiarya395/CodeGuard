"""Code Reader: what one Python file contains, read with the ast module only (never run).

For each file it lists functions and classes, imports, the decorators on each function (as full
dotted names), framework routes (Flask, FastAPI, Django, Django REST framework) and the places
where outside input enters. Names are resolved with the same NameResolver as the AST rule checks,
so `from flask import request as r; r.args` is seen as flask.request.args.

These facts are used by the taint check, the logic-flaw rules and the AI review (which is told
which routes, decorators and entry points each function has).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from codeguard.rulechecks.loader import TaintFile, TaintSource
from codeguard.rulechecks.pyast import NameResolver, file_index, name_matches
from codeguard.rulechecks.source import SourceFile

HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Django REST framework view set actions and the HTTP method each one answers.
VIEWSET_ACTIONS = {
    "list": "GET",
    "retrieve": "GET",
    "create": "POST",
    "update": "PUT",
    "partial_update": "PATCH",
    "destroy": "DELETE",
}

_FLASK_APPS = ("flask.Flask()", "flask.Blueprint()", "flask.blueprints.Blueprint()", "flask.app.Flask()")
_FASTAPI_APPS = ("fastapi.FastAPI()", "fastapi.APIRouter()", "fastapi.routing.APIRouter()", "starlette.routing.Router()")
_DJANGO_METHOD_DECORATORS = {
    "django.views.decorators.http.require_POST": ("POST",),
    "django.views.decorators.http.require_GET": ("GET",),
    "django.views.decorators.http.require_safe": ("GET", "HEAD"),
}
_DJANGO_VIEW_BASES = ("django.views.*", "rest_framework.views.*", "rest_framework.viewsets.*", "rest_framework.generics.*")
_DEPENDS = ("fastapi.Depends", "fastapi.params.Depends", "fastapi.Security", "fastapi.params.Security")
# Parameter types FastAPI fills in itself; they are not user input.
_FRAMEWORK_TYPES = re.compile(r"(^|\.)(Request|WebSocket|Response|BackgroundTasks|Session|AsyncSession|HTTPConnection)$")
_REQUEST_TYPES = re.compile(r"(^|\.)(Request|HttpRequest|WebSocket|HTTPConnection)$")
_PATH_VAR = re.compile(r"<(?:[^:<>]+:)?([A-Za-z_]\w*)>|\{([A-Za-z_]\w*)(?::[^}]*)?\}")


@dataclass
class Route:
    framework: str  # flask, fastapi, django, drf
    methods: tuple[str, ...]  # upper-case HTTP methods; empty = not known
    path: str | None
    line: int


@dataclass
class EntryPoint:
    kind: str  # web, cli, stdin, env, file (see rules/taint.yaml)
    source_id: str
    what: str  # e.g. "flask.request.args" or "parameter post_id"
    line: int
    function: str | None  # qualified name, or None for module-level code


@dataclass
class FunctionInfo:
    name: str
    qualname: str  # Class.method for methods
    line: int  # the "def" line
    line_start: int  # first decorator line (or the def line)
    line_end: int
    class_name: str | None
    params: list[str]
    decorators: list[str]  # full names; a decorator call gets "()", e.g. "flask.Flask().route()"
    node: ast.FunctionDef | ast.AsyncFunctionDef = field(repr=False)
    routes: list[Route] = field(default_factory=list)
    framework: str | None = None  # set when the function is a web view
    input_params: dict[str, str] = field(default_factory=dict)  # parameter -> source id
    request_param: str | None = None  # the parameter that holds the request object
    depends: list[str] = field(default_factory=list)  # FastAPI Depends(...) / Security(...) targets
    entry_points: list[EntryPoint] = field(default_factory=list)

    @property
    def is_view(self) -> bool:
        return self.framework is not None

    @property
    def methods(self) -> set[str]:
        return {m for r in self.routes for m in r.methods}

    @property
    def paths(self) -> list[str]:
        return [r.path for r in self.routes if r.path]


@dataclass
class ClassInfo:
    name: str
    line_start: int
    line_end: int
    bases: list[str]
    decorators: list[str]
    attrs: dict[str, ast.expr] = field(default_factory=dict, repr=False)  # class-level assignments
    node: ast.ClassDef = field(default=None, repr=False)  # type: ignore[assignment]

    @property
    def is_view(self) -> bool:
        return any(name_matches(b, list(_DJANGO_VIEW_BASES)) for b in self.bases) or any(
            b.rsplit(".", 1)[-1].endswith(("View", "ViewSet", "APIView")) for b in self.bases
        )


@dataclass
class ImportInfo:
    module: str
    names: list[str]
    line: int


@dataclass
class UrlRoute:
    """A Django urls.py entry: path("posts/<int:pk>/", views.post_detail)."""

    path: str | None
    view: str  # the view's function or class name
    line: int


@dataclass
class ModuleFacts:
    file: str
    parsed: bool
    imports: list[ImportInfo] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    url_routes: list[UrlRoute] = field(default_factory=list)

    def function(self, qualname: str) -> FunctionInfo | None:
        return next((f for f in self.functions if f.qualname == qualname), None)

    def function_at(self, line: int) -> FunctionInfo | None:
        """The innermost function whose lines include `line`."""
        hits = [f for f in self.functions if f.line_start <= line <= f.line_end]
        return min(hits, key=lambda f: f.line_end - f.line_start) if hits else None

    def cls(self, name: str | None) -> ClassInfo | None:
        return next((c for c in self.classes if c.name == name), None) if name else None


# --- Input sources (shared with the taint check) ---


def attribute_chain(node: ast.AST) -> tuple[str | None, list[str]]:
    """request.GET.get -> ("request", ["GET", "get"])."""
    attrs: list[str] = []
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        if isinstance(node, ast.Attribute):
            attrs.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            node = node.value
    return (node.id if isinstance(node, ast.Name) else None), attrs[::-1]


class SourceMatcher:
    """Recognises the input sources of rules/taint.yaml in an expression."""

    def __init__(self, taint: TaintFile):
        self.named = [s for s in taint.sources if s.names]
        self.request = [s for s in taint.sources if s.request_param]
        self.route = next((s for s in taint.sources if s.route_params), None)
        self.param_decorators = [s for s in taint.sources if s.param_decorators]

    def by_name(self, name: str | None) -> TaintSource | None:
        if not name:
            return None
        for src in self.named:
            for n in src.names:
                if name == n or name.startswith((n + ".", n + "(", n + "[")):
                    return src
        return None

    def is_whole_body(self, src: TaintSource, name: str) -> bool:
        return any(name == n or name == n + "()" for n in src.whole_body)

    def by_request_param(self, attrs: list[str]) -> TaintSource | None:
        if not attrs:
            return None
        return next((s for s in self.request if attrs[0] in s.request_param), None)

    def match(self, node: ast.AST, scope: "Scope", request_param: str | None):
        """(source, description) when `node` itself reads input, else None. Sub-expressions are
        not searched; the caller walks the expression."""
        if isinstance(node, ast.Call):
            target: ast.AST = node.func
        elif isinstance(node, (ast.Attribute, ast.Name)):
            target = node
        else:
            return None
        root, attrs = attribute_chain(target)
        if request_param and root == request_param:
            src = self.by_request_param(attrs)
            if src:
                return src, f"{root}.{'.'.join(attrs[:2])}"
            return None
        name = scope.qname(target)
        src = self.by_name(name)
        if src:
            return src, name
        return None


# --- Reading one file ---


def read_module(src: SourceFile, taint: TaintFile) -> ModuleFacts:
    facts = ModuleFacts(file=src.rel, parsed=src.tree is not None)
    if src.tree is None:
        return facts
    resolver = file_index(src).resolver
    matcher = SourceMatcher(taint)
    tree = src.tree

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                facts.imports.append(ImportInfo(a.name, [a.asname or a.name.split(".")[0]], node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            facts.imports.append(ImportInfo(node.module, [a.asname or a.name for a in node.names], node.lineno))
    facts.frameworks = _frameworks(facts.imports)

    for node, cls in _definitions(tree):
        if isinstance(node, ast.ClassDef):
            facts.classes.append(_class_info(node, resolver))
        else:
            facts.functions.append(_function_info(node, cls, resolver, facts, matcher))

    facts.url_routes = _django_urls(tree, resolver)
    _attach_url_routes(facts, facts.url_routes)
    for fn in facts.functions:
        fn.entry_points = _entry_points(fn.node, fn, resolver, matcher)
        facts.entry_points += fn.entry_points
    facts.entry_points += _entry_points(_module_code(tree), None, resolver, matcher)
    facts.entry_points.sort(key=lambda e: e.line)
    return facts


def _frameworks(imports: list[ImportInfo]) -> set[str]:
    out: set[str] = set()
    for imp in imports:
        top = imp.module.split(".")[0]
        if top in ("flask", "flask_login", "flask_wtf", "flask_sqlalchemy", "flask_jwt_extended", "flask_cors"):
            out.add("flask")
        elif top in ("fastapi", "starlette"):
            out.add("fastapi")
        elif top == "django":
            out.add("django")
        elif top == "rest_framework":
            out.update(("django", "drf"))
        elif top in ("click", "typer", "argparse"):
            out.add("cli")
    return out


def _definitions(tree: ast.Module):
    """(function or class node, enclosing class name) for module-level definitions and methods.
    Functions nested inside functions are part of their parent."""
    for node in tree.body:
        yield from _defs_in(node, None)


def _defs_in(node: ast.AST, cls: str | None):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        yield node, cls
    elif isinstance(node, ast.ClassDef):
        yield node, cls
        for child in node.body:
            yield from _defs_in(child, node.name)
    elif isinstance(node, (ast.If, ast.Try, ast.With)):
        # e.g. definitions inside "if TYPE_CHECKING:" or "try: ... except ImportError:"
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                yield from _defs_in(child, cls)


def _module_code(tree: ast.Module) -> ast.Module:
    """The module's own statements, without function and class bodies."""
    body = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    return ast.Module(body=body, type_ignores=[])


def decorator_name(dec: ast.expr, resolver: NameResolver) -> str:
    target = dec.func if isinstance(dec, ast.Call) else dec
    name = resolver.resolve(target) or ast.unparse(target)
    return name + "()" if isinstance(dec, ast.Call) else name


def _class_info(node: ast.ClassDef, resolver: NameResolver) -> ClassInfo:
    attrs: dict[str, ast.expr] = {}
    for stmt in node.body:
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    attrs[t.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            attrs[stmt.target.id] = stmt.value
    start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
    return ClassInfo(
        name=node.name,
        line_start=start,
        line_end=node.end_lineno or node.lineno,
        bases=[resolver.resolve(b) or ast.unparse(b) for b in node.bases],
        decorators=[decorator_name(d, resolver) for d in node.decorator_list],
        attrs=attrs,
        node=node,
    )


def _params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    a = node.args
    return [*a.posonlyargs, *a.args, *([a.vararg] if a.vararg else []), *a.kwonlyargs, *([a.kwarg] if a.kwarg else [])]


def _defaults(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.expr]:
    a = node.args
    positional = [*a.posonlyargs, *a.args]
    out = {p.arg: d for p, d in zip(positional[len(positional) - len(a.defaults) :], a.defaults)}
    out.update({p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})
    return out


def _function_info(node, cls: str | None, resolver: NameResolver, facts: ModuleFacts, matcher: SourceMatcher) -> FunctionInfo:
    params = [p.arg for p in _params(node)]
    start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
    fn = FunctionInfo(
        name=node.name,
        qualname=f"{cls}.{node.name}" if cls else node.name,
        line=node.lineno,
        line_start=start,
        line_end=node.end_lineno or node.lineno,
        class_name=cls,
        params=params,
        decorators=[decorator_name(d, resolver) for d in node.decorator_list],
        node=node,
    )
    for dec in node.decorator_list:
        route = _route(dec, resolver, facts.frameworks)
        if route:
            fn.routes.append(route)
    if fn.routes:
        fn.framework = fn.routes[0].framework

    # Django / DRF function views, and the HTTP methods their decorators allow.
    methods: tuple[str, ...] = ()
    for dec, name in zip(node.decorator_list, fn.decorators):
        bare = name.removesuffix("()")
        if bare in _DJANGO_METHOD_DECORATORS:
            methods = _DJANGO_METHOD_DECORATORS[bare]
        elif bare == "django.views.decorators.http.require_http_methods" and isinstance(dec, ast.Call) and dec.args:
            methods = _constant_strings(dec.args[0])
        elif bare in ("rest_framework.decorators.api_view",):
            methods = _constant_strings(dec.args[0]) if isinstance(dec, ast.Call) and dec.args else ("GET",)
            fn.routes.append(Route("drf", methods, None, dec.lineno))
            fn.framework = "drf"
    # Methods of Django class-based views and DRF view sets: get/post/... and create/destroy/...
    owner = facts.cls(cls)
    if fn.framework is None and owner is not None and owner.is_view:
        action = _drf_action(node, fn.decorators)
        verb = node.name.upper() if node.name in HTTP_VERBS else VIEWSET_ACTIONS.get(node.name)
        verb_methods = action if action is not None else ((verb,) if verb else ())
        if verb_methods:
            fw = "drf" if any(b.startswith("rest_framework") for b in owner.bases) else "django"
            fn.framework = fw
            fn.routes.append(Route(fw, verb_methods, None, node.lineno))
        else:
            return _finish_params(fn, node, resolver, matcher)  # a helper method, not a view

    first = params[1] if cls and len(params) > 1 else (params[0] if params else None)
    if fn.framework is None and "django" in facts.frameworks and first == "request":
        fn.framework = "django"
        fn.routes.append(Route("django", methods or _methods_checked_in_body(node), None, node.lineno))
    elif fn.framework in ("django", "drf") and methods and not fn.routes[0].methods:
        fn.routes[0].methods = methods
    return _finish_params(fn, node, resolver, matcher)


def _finish_params(fn: FunctionInfo, node, resolver: NameResolver, matcher: SourceMatcher) -> FunctionInfo:
    params = fn.params

    # Which parameters carry input, which hold the request, which are FastAPI dependencies.
    defaults = _defaults(node)
    annotations = {p.arg: p.annotation for p in _params(node)}
    for p in params:
        if p in ("self", "cls"):
            continue
        ann = annotations.get(p)
        ann_name = (resolver.resolve(ann) or ast.unparse(ann)) if ann is not None else ""
        dep = _dependency(defaults.get(p), ann, resolver)
        if dep is not None:
            fn.depends.append(dep)
            continue
        if p == "request" or (ann is not None and _REQUEST_TYPES.search(ann_name)):
            fn.request_param = p
            continue
        if fn.framework in ("flask", "fastapi", "django") and matcher.route is not None:
            if fn.framework == "fastapi" and ann is not None and _FRAMEWORK_TYPES.search(ann_name):
                continue
            fn.input_params[p] = matcher.route.id
    for src in matcher.param_decorators:
        if any(name_matches(d.removesuffix("()"), src.param_decorators) for d in fn.decorators):
            for p in params:
                if p not in ("self", "cls"):
                    fn.input_params.setdefault(p, src.id)
    return fn


def _route(dec: ast.expr, resolver: NameResolver, frameworks: set[str]) -> Route | None:
    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
        return None
    verb = dec.func.attr
    if verb not in (*HTTP_VERBS, "route", "api_route"):
        return None
    base = resolver.resolve(dec.func.value) or ""
    if base in _FLASK_APPS:
        fw = "flask"
    elif base in _FASTAPI_APPS:
        fw = "fastapi"
    elif "flask" in frameworks and not base.startswith(("fastapi.", "starlette.")):
        fw = "flask"  # e.g. "from app import app" in a routes file
    elif "fastapi" in frameworks:
        fw = "fastapi"
    else:
        return None
    if fw == "flask" and verb == "api_route":
        return None
    path = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str) else None
    for kw in dec.keywords:
        if kw.arg in ("rule", "path") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            path = kw.value.value
    if verb in HTTP_VERBS:
        methods: tuple[str, ...] = (verb.upper(),)
    else:
        given = next((kw.value for kw in dec.keywords if kw.arg == "methods"), None)
        methods = _constant_strings(given) if given is not None else (("GET",) if fw == "flask" else ())
    return Route(fw, tuple(m.upper() for m in methods), path, dec.lineno)


def _constant_strings(node: ast.expr | None) -> tuple[str, ...]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return tuple(e.value.upper() for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str))
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value.upper(),)
    return ()


def _methods_checked_in_body(node: ast.AST) -> tuple[str, ...]:
    """Django function views often branch on  if request.method == "POST":  instead of a decorator."""
    found: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Compare) and isinstance(n.left, ast.Attribute) and n.left.attr == "method":
            for comp in n.comparators:
                for m in _constant_strings(comp):
                    if m not in found:
                        found.append(m)
    return tuple(found)


def _drf_action(node, decorators: list[str]) -> tuple[str, ...] | None:
    for dec, name in zip(node.decorator_list, decorators):
        if name.removesuffix("()").endswith(("rest_framework.decorators.action", ".action")) and isinstance(dec, ast.Call):
            given = next((kw.value for kw in dec.keywords if kw.arg == "methods"), None)
            return _constant_strings(given) if given is not None else ("GET",)
    return None


def _dependency(default: ast.expr | None, ann: ast.expr | None, resolver: NameResolver) -> str | None:
    """The target of a FastAPI Depends(...) / Security(...) parameter, or None."""
    calls = []
    if isinstance(default, ast.Call):
        calls.append(default)
    if isinstance(ann, ast.Subscript):  # Annotated[User, Depends(get_current_user)]
        calls += [n for n in ast.walk(ann) if isinstance(n, ast.Call)]
    for call in calls:
        if (resolver.resolve(call.func) or "") in _DEPENDS:
            if call.args:
                return (resolver.resolve(call.args[0]) or ast.unparse(call.args[0])).rsplit(".", 1)[-1]
            return "Depends()"
    return None


def _django_urls(tree: ast.Module, resolver: NameResolver) -> list[UrlRoute]:
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        if resolver.resolve(node.func) not in ("django.urls.path", "django.urls.re_path", "django.conf.urls.url"):
            continue
        path = node.args[0].value if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) else None
        view = node.args[1]
        if isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute) and view.func.attr == "as_view":
            view = view.func.value
        if isinstance(view, (ast.Name, ast.Attribute)):
            out.append(UrlRoute(path, view.id if isinstance(view, ast.Name) else view.attr, node.lineno))
    return out


def _attach_url_routes(facts: ModuleFacts, urls: list[UrlRoute]) -> None:
    """Give Django views the URL path from a urls.py in the same scan (matched by name)."""
    for url in urls:
        for fn in facts.functions:
            if fn.framework == "django" and (fn.name == url.view or fn.class_name == url.view):
                for r in fn.routes:
                    r.path = r.path or url.path
                if url.path:
                    for name in _PATH_VAR.findall(url.path):
                        var = name[0] or name[1]
                        if var in fn.params:
                            fn.input_params.setdefault(var, "route-parameter")


def attach_project_urls(modules: list[ModuleFacts]) -> None:
    """urls.py and views.py are separate files; match views across the whole scan."""
    urls = [u for m in modules for u in m.url_routes]
    if urls:
        for m in modules:
            _attach_url_routes(m, urls)


def _local_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        names.update(p.arg for p in _params(node))
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            names.add(n.id)
        elif isinstance(n, ast.arg) and n is not node:
            names.add(n.arg)
    return names


class Scope:
    """Name resolution inside one function (or the module's own code).

    Local variables are resolved through their own assignment in this scope
    (parser = argparse.ArgumentParser(); parser.parse_args -> argparse.ArgumentParser().parse_args),
    never through a same-named variable elsewhere in the file. A local assigned more than once,
    or from something other than a call, has no name (None).
    """

    def __init__(self, node: ast.AST, resolver: NameResolver):
        self.resolver = resolver
        self.locals = _local_names(node)
        self.local_calls = local_call_bindings(node, resolver, self.locals)

    def qname(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.locals:
                return self.local_calls.get(node.id)
            return self.resolver.resolve(node)
        if isinstance(node, ast.Attribute):
            base = self.qname(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            base = self.qname(node.func)
            return f"{base}()" if base else None
        return None


def local_call_bindings(node: ast.AST, resolver: NameResolver, locals_: set[str]) -> dict[str, str | None]:
    """Local variables assigned exactly from calls in this scope:  parser = argparse.ArgumentParser()."""
    out: dict[str, str | None] = {}
    seen: set[str] = set()
    body = node.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)) else []
    for stmt in body:
        for n in ast.walk(stmt):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            pairs: list[tuple[ast.AST, ast.AST | None]] = []
            if isinstance(n, ast.Assign):
                pairs = [(t, n.value) for t in n.targets]
            elif isinstance(n, ast.AnnAssign):
                pairs = [(n.target, n.value)]
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                pairs = [(i.optional_vars, i.context_expr) for i in n.items if i.optional_vars is not None]
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.AugAssign)):
                pairs = [(n.target, None)]
            for target, value in pairs:
                if not isinstance(target, ast.Name):
                    continue
                if target.id in seen:
                    out[target.id] = None  # assigned more than once: unknown
                    continue
                seen.add(target.id)
                out[target.id] = _resolve_with(value, resolver, out, locals_) if isinstance(value, ast.Call) else None
    return out


def _resolve_with(node: ast.AST, resolver: NameResolver, local: dict[str, str | None], locals_: set[str]) -> str | None:
    if isinstance(node, ast.Name):
        if node.id in locals_:
            return local.get(node.id)
        return resolver.resolve(node)
    if isinstance(node, ast.Attribute):
        base = _resolve_with(node.value, resolver, local, locals_)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call):
        base = _resolve_with(node.func, resolver, local, locals_)
        return f"{base}()" if base else None
    return None


def _entry_points(node: ast.AST, fn: FunctionInfo | None, resolver: NameResolver, matcher: SourceMatcher) -> list[EntryPoint]:
    qual = fn.qualname if fn else None
    out: list[EntryPoint] = []
    if fn is not None:
        for p, sid in fn.input_params.items():
            src = next((s for s in matcher.named + matcher.param_decorators if s.id == sid), matcher.route)
            kind = src.kind if src else "web"
            out.append(EntryPoint(kind, sid, f"parameter {p}", fn.line, qual))
    scope = Scope(node, resolver)
    seen: set[tuple[int, str]] = set()
    body = node.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)) else [node]
    for stmt in body:
        for n in ast.walk(stmt):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            root, _ = attribute_chain(n.func if isinstance(n, ast.Call) else n)
            if root in scope.locals and matcher.by_name(scope.local_calls.get(root)):
                continue  # a variable holding input that was read earlier (listed where it was read)
            hit = matcher.match(n, scope, fn.request_param if fn else None)
            if not hit:
                continue
            src, what = hit
            key = (n.lineno, src.id)
            if key in seen:
                continue
            seen.add(key)
            out.append(EntryPoint(src.kind, src.id, what, n.lineno, qual))
    return out
