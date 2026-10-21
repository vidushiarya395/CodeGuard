"""Logic-flaw checks (rules/logic_flaws.yaml), no AI.

These checks look at what a web route does and whether anything protects it, using the Code
Reader's facts (routes, decorators, parameters) and the word lists in the rule file's "signals".
They are written to stay quiet when the evidence is unclear: anything that looks like a login or
permission check counts as one, even if it might be weak.

Rules with "patterns" (CSRF turned off, cookie flags) use the same AST matcher as
insecure_settings.yaml; the named checks are below.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from codeguard.cwe import CweGroups
from codeguard.models import Finding
from codeguard.reader import FunctionInfo, ModuleFacts, ProjectFacts, SourceMatcher
from codeguard.reader.facts import WRITE_METHODS, ClassInfo, Scope, attribute_chain
from codeguard.rulechecks.loader import LogicRule, LogicSignals, Rulebook
from codeguard.rulechecks.pyast import check_ast_rules, file_index, name_matches
from codeguard.rulechecks.source import SourceFile, make_finding

_I = re.IGNORECASE
_AUTH_MIXINS = re.compile(r"(LoginRequired|PermissionRequired|UserPassesTest|Access)Mixin$")
_ROLE_MIXINS = re.compile(r"(PermissionRequired|UserPassesTest)Mixin$")
_OPEN_PERMISSIONS = re.compile(r"(^|\.)AllowAny$")
_LOGIN_ONLY_PERMISSIONS = re.compile(r"(^|\.)(AllowAny|IsAuthenticated|IsAuthenticatedOrReadOnly)$")
_VIEWSET_BASE = re.compile(r"(ViewSet|ViewSetMixin)$")
_WRITABLE_BASE = re.compile(r"(ModelViewSet|Create\w*|Update\w*|Destroy\w*)$")
_WRITE_ACTIONS = ("create", "update", "partial_update", "destroy", "post", "put", "patch", "delete")
_UPLOAD_SAVE = re.compile(r"(^|\.)(save|write|write_bytes|writelines|copyfileobj|upload_fileobj|put_object)$")
_NAME_CLEANERS = ("werkzeug.utils.secure_filename", "werkzeug.secure_filename", "os.path.basename")
_ALL_ORIGINS = (".*", "^.*$", ".+", "^.+$", "*")
_SETTINGS_FILE = re.compile(r"(^|/)settings(\.py$|/)")


@dataclass
class _Project:
    """Facts that span files: does the app protect any route, and are there global guards?"""

    any_auth: bool = False
    flask_guard: bool = False  # a before_request hook that checks the login
    fastapi_guard: bool = False  # FastAPI(dependencies=[...]) / APIRouter / include_router
    django_login_middleware: bool = False
    drf_default: str | None = None  # "open", "closed", or None when no settings file was scanned
    django_settings_seen: bool = False
    notes: list[str] = field(default_factory=list)


class LogicChecker:
    def __init__(self, book: Rulebook, groups: CweGroups, project: ProjectFacts, sources: dict[str, SourceFile]):
        self.book = book
        self.groups = groups
        self.facts = project
        self.sources = sources
        sig: LogicSignals = book.logic.signals
        self.sig = sig
        self.auth_dec = re.compile(sig.auth_decorator_regex, _I)
        self.role_dec = re.compile(sig.role_decorator_regex, _I)
        self.auth_attr = re.compile(sig.auth_attribute_regex, _I)
        self.role_re = re.compile(sig.role_regex, _I)
        self.public = re.compile(sig.public_route_regex, _I)
        self.sensitive = re.compile(sig.sensitive_route_regex, _I)
        self.admin = re.compile(sig.admin_route_regex, _I)
        self.sql_write = re.compile(sig.sql_write_regex, _I)
        self.sql_destructive = re.compile(sig.sql_destructive_regex, _I)
        self.id_param = re.compile(sig.id_param_regex, _I)
        self.ownership = re.compile(sig.ownership_regex, _I)
        self.upload_check = re.compile(sig.upload_check_regex, _I)
        self.db_dep = re.compile(sig.db_dependency_regex, _I)
        self.matcher = SourceMatcher(book.taint)
        self.rules = {r.check: r for r in book.logic.rules if r.check}
        self.pattern_rules = [r for r in book.logic.rules if r.patterns]
        self.project = self._project()

    # --- whole-project facts ---

    def _project(self) -> _Project:
        p = _Project()
        for rel, mod in self.facts.modules.items():
            src = self.sources.get(rel)
            if src is None or src.tree is None:
                continue
            resolver = file_index(src).resolver
            for fn in mod.functions:
                if any(d.removesuffix("()").endswith(("before_request", "before_app_request")) for d in fn.decorators):
                    if self._body_auth(fn, src):
                        p.flask_guard = True
                if fn.is_view and self.has_auth(fn, mod, src, include_global=False):
                    p.any_auth = True
            for node in ast.walk(src.tree):
                if isinstance(node, ast.Call):
                    name = resolver.resolve(node.func) or ""
                    if name in ("fastapi.FastAPI", "fastapi.APIRouter", "fastapi.routing.APIRouter") or name.endswith(
                        ".include_router"
                    ):
                        if self._auth_dependencies(node, resolver):
                            p.fastapi_guard = True
            if _SETTINGS_FILE.search(rel):
                p.django_settings_seen = True
                self._read_settings(src, p)
        if p.flask_guard or p.fastapi_guard or p.django_login_middleware or p.drf_default == "closed":
            p.any_auth = True
        return p

    def _read_settings(self, src: SourceFile, p: _Project) -> None:
        values = _module_assignments(src.tree)
        middleware = values.get("MIDDLEWARE")
        if middleware is not None and any(
            isinstance(n, ast.Constant) and isinstance(n.value, str) and "LoginRequiredMiddleware" in n.value
            for n in ast.walk(middleware)
        ):
            p.django_login_middleware = True
        rf = values.get("REST_FRAMEWORK")
        default = None
        if isinstance(rf, ast.Dict):
            for k, v in zip(rf.keys, rf.values):
                if isinstance(k, ast.Constant) and k.value == "DEFAULT_PERMISSION_CLASSES":
                    default = v
        if default is None:
            p.drf_default = p.drf_default or "open"  # DRF's own default is AllowAny
        else:
            names = [n.value for n in ast.walk(default) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
            p.drf_default = "open" if names and all(_OPEN_PERMISSIONS.search(n) for n in names) else "closed"

    # --- signals ---

    def _auth_dependencies(self, call: ast.Call, resolver) -> bool:
        for kw in call.keywords:
            if kw.arg == "dependencies":
                for n in ast.walk(kw.value):
                    if isinstance(n, ast.Call) and (resolver.resolve(n.func) or "").endswith(("Depends", "Security")):
                        target = n.args[0] if n.args else None
                        name = (resolver.resolve(target) or "").rsplit(".", 1)[-1] if target is not None else ""
                        if not name or not self.db_dep.search(name):
                            return True
        return False

    def _decorator_auth(self, names: list[str], nodes: list[ast.expr], resolver, regex) -> bool:
        for name in names:
            if regex.search(name.removesuffix("()").rsplit(".", 1)[-1]):
                return True
        for dec in nodes:  # method_decorator(login_required), @app.get("/x", dependencies=[...])
            if isinstance(dec, ast.Call):
                for a in dec.args:
                    inner = (resolver.resolve(a.func if isinstance(a, ast.Call) else a) or "").rsplit(".", 1)[-1]
                    if inner and regex.search(inner):
                        return True
                if regex is self.auth_dec and self._auth_dependencies(dec, resolver):
                    return True
        return False

    def _body_auth(self, fn: FunctionInfo, src: SourceFile) -> bool:
        resolver = file_index(src).resolver
        scope = Scope(fn.node, resolver)
        for n in _walk_body(fn.node):
            if isinstance(n, (ast.Name, ast.Attribute)) and isinstance(getattr(n, "ctx", None), ast.Load):
                name = scope.qname(n)
                if name and name_matches(name, self.sig.auth_names):
                    return True
                if isinstance(n, ast.Attribute) and self.auth_attr.match(n.attr):
                    return True
                root, attrs = attribute_chain(n)
                if fn.request_param and root == fn.request_param and attrs[:1] == ["user"]:
                    return True
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) and self.auth_attr.match(n.value):
                return True
            elif isinstance(n, ast.Call) and _has_status(n, (401, 403)):
                return True
        return False

    def has_auth(self, fn: FunctionInfo, mod: ModuleFacts, src: SourceFile, include_global: bool = True) -> bool:
        resolver = file_index(src).resolver
        if self._decorator_auth(fn.decorators, fn.node.decorator_list, resolver, self.auth_dec):
            return True
        if any(not self.db_dep.search(d) for d in fn.depends):
            return True
        owner = mod.cls(fn.class_name)
        if owner is not None and self._class_auth(owner, resolver):
            return True
        if self._body_auth(fn, src):
            return True
        if include_global:
            p = self.project
            if fn.framework == "flask" and p.flask_guard:
                return True
            if fn.framework == "fastapi" and p.fastapi_guard:
                return True
            if fn.framework in ("django", "drf") and p.django_login_middleware:
                return True
            if fn.framework == "drf" and p.drf_default == "closed" and not (owner and "permission_classes" in owner.attrs):
                return True
        return False

    def _class_auth(self, cls: ClassInfo, resolver) -> bool:
        if any(_AUTH_MIXINS.search(b) for b in cls.bases):
            return True
        if self._decorator_auth(cls.decorators, cls.node.decorator_list, resolver, self.auth_dec):
            return True
        perms = cls.attrs.get("permission_classes")
        if perms is not None:
            names = _class_names(perms, resolver)
            if names and not all(_OPEN_PERMISSIONS.search(n) for n in names):
                return True
        return "get_permissions" in _method_names(cls)  # custom permission logic: assume it checks

    def has_role(self, fn: FunctionInfo, mod: ModuleFacts, src: SourceFile) -> bool:
        resolver = file_index(src).resolver
        if self._decorator_auth(fn.decorators, fn.node.decorator_list, resolver, self.role_dec):
            return True
        if any(re.search(r"admin|role|perm|superuser|staff", d, _I) for d in fn.depends):
            return True
        owner = mod.cls(fn.class_name)
        if owner is not None:
            if any(_ROLE_MIXINS.search(b) for b in owner.bases):
                return True
            perms = owner.attrs.get("permission_classes")
            if perms is not None and any(not _LOGIN_ONLY_PERMISSIONS.search(n) for n in _class_names(perms, resolver)):
                return True
        for n in _walk_body(fn.node):
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) and self.role_re.match(n.attr):
                return True  # user.is_admin (reading it), not user.role = "admin" (setting it)
            if isinstance(n, ast.Call):
                last = n.func.attr if isinstance(n.func, ast.Attribute) else (n.func.id if isinstance(n.func, ast.Name) else "")
                if self.role_re.match(last or "") or _has_status(n, (403,)):
                    return True
            if isinstance(n, ast.Compare):
                for c in [n.left, *n.comparators]:
                    if isinstance(c, ast.Constant) and isinstance(c.value, str) and self.role_re.match(c.value):
                        return True
        return False

    def is_public(self, fn: FunctionInfo) -> bool:
        return bool(self.public.search(fn.name)) or any(self.public.search(p) for p in fn.paths)

    # --- what a route does ---

    def _calls(self, fn: FunctionInfo, src: SourceFile):
        """(call node, full name) for every call in the function body."""
        scope = Scope(fn.node, file_index(src).resolver)
        for n in _walk_body(fn.node):
            if isinstance(n, ast.Call):
                name = scope.qname(n.func) or _text(n.func)
                yield n, name

    def _sql_text(self, call: ast.Call) -> str:
        if not call.args:
            return ""
        parts = [n.value for n in ast.walk(call.args[0]) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        return parts[0] if parts else ""

    def actions(self, fn: FunctionInfo, src: SourceFile) -> tuple[list[str], list[str]]:
        """(what it deletes / does that is sensitive, what it writes)."""
        destructive: list[str] = []
        writes: list[str] = []
        for call, name in self._calls(fn, src):
            if not name:
                continue
            short = name.replace("()", "").rsplit(".", 2)
            label = ".".join(short[-2:]) if len(short) > 1 else short[0]
            if name_matches(name, self.sig.destructive_calls):
                destructive.append(f"{label}() on line {call.lineno}")
            elif name_matches(name, self.sig.write_calls):
                writes.append(f"{label}() on line {call.lineno}")
            if name.endswith((".execute", ".executemany", ".executescript")):
                sql = self._sql_text(call)
                if self.sql_destructive.match(sql):
                    destructive.append(f"SQL {sql.split()[0].upper()} on line {call.lineno}")
                elif self.sql_write.match(sql):
                    writes.append(f"SQL {sql.split()[0].upper()} on line {call.lineno}")
        if "DELETE" in fn.methods:
            destructive.insert(0, "it answers HTTP DELETE")
        return destructive, writes

    # --- the checks ---

    def check_file(self, src: SourceFile, mod: ModuleFacts) -> list[Finding]:
        findings = check_ast_rules(src, self.pattern_rules, self.groups) if self.pattern_rules else []
        if src.tree is None or not mod.parsed:
            return findings
        for check, rule in self.rules.items():
            fn = getattr(self, f"_check_{check}")
            findings += fn(rule, src, mod)
        return findings

    def _views(self, mod: ModuleFacts):
        for fn in mod.functions:
            if not fn.is_view:
                continue
            owner = mod.cls(fn.class_name)
            if owner is not None and any(_VIEWSET_BASE.search(b) for b in owner.bases):
                continue  # view sets are checked as a whole by drf_open_viewset
            yield fn

    def _route_label(self, fn: FunctionInfo) -> str:
        methods = "/".join(sorted(fn.methods)) or "any method"
        path = f" {fn.paths[0]}" if fn.paths else ""
        return f"{fn.qualname}() ({methods}{path})"

    def _check_missing_authentication(self, rule: LogicRule, src: SourceFile, mod: ModuleFacts) -> list[Finding]:
        out = []
        for fn in self._views(mod):
            if self.is_public(fn) or self.has_auth(fn, mod, src):
                continue
            destructive, writes = self.actions(fn, src)
            sensitive = self.sensitive.search(fn.name) or next((m for p in fn.paths if (m := self.sensitive.search(p))), None)
            changes = writes or (fn.methods & WRITE_METHODS)
            if destructive:
                why = f"It deletes data ({destructive[0]}) and has no login or permission check."
            elif sensitive:
                why = f"Its name or URL marks a sensitive action ('{sensitive.group(0)}') and it has no login or permission check."
            elif changes and self.project.any_auth:
                what = writes[0] if writes else "it accepts " + "/".join(sorted(fn.methods & WRITE_METHODS))
                why = f"It changes data ({what}) while other routes in this app require a login."
            else:
                continue
            out.append(self._at_def(rule, src, fn, f"Route {self._route_label(fn)}. {why}"))
        return out

    def _check_missing_authorization(self, rule: LogicRule, src: SourceFile, mod: ModuleFacts) -> list[Finding]:
        out = []
        for fn in self._views(mod):
            hit = self.admin.search(fn.name) or next((m for p in fn.paths if (m := self.admin.search(p))), None)
            if not hit or self.is_public(fn):
                continue
            if self.has_auth(fn, mod, src) and not self.has_role(fn, mod, src):
                detail = (
                    f"Route {self._route_label(fn)} looks like an admin action ('{hit.group(0)}'): it checks the "
                    "login but no role or permission."
                )
                out.append(self._at_def(rule, src, fn, detail))
        return out

    def _check_idor(self, rule: LogicRule, src: SourceFile, mod: ModuleFacts) -> list[Finding]:
        out = []
        for fn in self._views(mod):
            ids = [p for p in fn.input_params if self.id_param.match(p)]
            if not ids or not self.has_auth(fn, mod, src) or self.has_role(fn, mod, src):
                continue
            fetch = None
            texts: list[str] = []
            for call, name in self._calls(fn, src):
                is_fetch = bool(name) and name_matches(name, self.sig.fetch_calls)
                if is_fetch:
                    texts.append(_text(call))
                    if fetch is None and _uses_names(call, ids):
                        fetch = call
            for n in _walk_body(fn.node):
                if isinstance(n, (ast.Compare, ast.If, ast.Assert, ast.IfExp)):
                    texts.append(_text(n.test if isinstance(n, (ast.If, ast.Assert, ast.IfExp)) else n))
            if fetch is None:
                continue
            id_words = re.compile(r"\b(" + "|".join(map(re.escape, ids)) + r")\b")
            if any(self.ownership.search(id_words.sub("_", t)) for t in texts):
                continue
            used = next(p for p in ids if _uses_names(fetch, [p]))
            detail = (
                f"Route {self._route_label(fn)} loads an object with the user-supplied '{used}' on line "
                f"{fetch.lineno} and never compares it with the logged-in user."
            )
            out.append(make_finding(rule, src, fetch.lineno, fetch.end_lineno or fetch.lineno, self.groups, detail=detail))
        return out

    def _check_unrestricted_upload(self, rule: LogicRule, src: SourceFile, mod: ModuleFacts) -> list[Finding]:
        out = []
        resolver = file_index(src).resolver
        for fn in mod.functions:
            scope = Scope(fn.node, resolver)
            uploads = self._upload_vars(fn, scope)
            if not uploads:
                continue
            save = None
            cleaned = False
            checked = False
            for n in _walk_body(fn.node):
                if isinstance(n, ast.Call):
                    name = scope.qname(n.func) or _text(n.func)
                    if name and name_matches(name, self.sig.upload_check_calls):
                        checked = True
                    if name in _NAME_CLEANERS:
                        cleaned = True
                    if save is None and _UPLOAD_SAVE.search(name or "") and _touches(n, uploads):
                        save = n
                tests = []
                if isinstance(n, (ast.If, ast.While, ast.Assert, ast.IfExp)):
                    tests.append(n.test)
                elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
                    tests.append(n.value.func)
                if any(self.upload_check.search(_text(t)) for t in tests):
                    checked = True
            if save is None or checked:
                continue
            detail = f"{fn.qualname}() saves an upload on line {save.lineno} without checking its extension or type."
            if not cleaned:
                detail += " The user's own file name is used as it is."
            out.append(make_finding(rule, src, save.lineno, save.end_lineno or save.lineno, self.groups, detail=detail))
        return out

    def _upload_vars(self, fn: FunctionInfo, scope: Scope) -> set[str]:
        uploads: set[str] = set()
        for p in fn.params:
            ann = next((a.annotation for a in _all_args(fn.node) if a.arg == p), None)
            if ann is not None and "UploadFile" in _text(ann):
                uploads.add(p)
        for n in _walk_body(fn.node):
            if isinstance(n, ast.Assign) and self._is_upload(n.value, fn, scope, uploads):
                uploads |= {t.id for t in n.targets if isinstance(t, ast.Name)}
            elif isinstance(n, (ast.For, ast.AsyncFor)) and self._is_upload(n.iter, fn, scope, uploads):
                if isinstance(n.target, ast.Name):
                    uploads.add(n.target.id)
        return uploads

    def _is_upload(self, node: ast.AST, fn: FunctionInfo, scope: Scope, uploads: set[str]) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in uploads:
                return True
            if isinstance(n, (ast.Attribute, ast.Call)):
                target = n.func if isinstance(n, ast.Call) else n
                root, attrs = attribute_chain(target)
                if fn.request_param and root == fn.request_param and attrs[:1] == ["FILES"]:
                    return True
                if (scope.qname(target) or "").startswith("flask.request.files"):
                    return True
        return False

    def _check_mass_assignment(self, rule: LogicRule, src: SourceFile, mod: ModuleFacts) -> list[Finding]:
        out = []
        resolver = file_index(src).resolver
        for fn in mod.functions:
            scope = Scope(fn.node, resolver)
            whole: set[str] = set()
            for n in _walk_body(fn.node):
                if isinstance(n, ast.Assign) and self._is_whole(n.value, fn, scope, whole):
                    whole |= {t.id for t in n.targets if isinstance(t, ast.Name)}
            for n in _walk_body(fn.node):
                hit = None
                if isinstance(n, ast.Call):
                    callee = scope.qname(n.func) or _text(n.func)
                    last = callee.replace("()", "").rsplit(".", 1)[-1] if callee else ""
                    starred = [kw.value for kw in n.keywords if kw.arg is None]
                    if starred and any(self._is_whole(v, fn, scope, whole) for v in starred):
                        if last[:1].isupper() or last in ("create", "update", "update_or_create", "get_or_create"):
                            hit = f"{last}(**...)"
                    elif last == "update" and n.args and self._is_whole(n.args[0], fn, scope, whole):
                        recv = _text(n.func.value) if isinstance(n.func, ast.Attribute) else ""
                        if "__dict__" in recv or recv.startswith("vars("):
                            hit = f"{recv}.update(...)"
                elif isinstance(n, (ast.For, ast.AsyncFor)) and isinstance(n.iter, ast.Call):
                    it = n.iter
                    if isinstance(it.func, ast.Attribute) and it.func.attr == "items" and self._is_whole(it.func.value, fn, scope, whole):
                        for m in ast.walk(n):
                            if isinstance(m, ast.Call) and isinstance(m.func, ast.Name) and m.func.id == "setattr":
                                hit = "setattr() for every key"
                                n = m
                                break
                if hit:
                    detail = f"{fn.qualname}(): the whole request body goes into {hit} on line {n.lineno}."
                    out.append(make_finding(rule, src, n.lineno, n.end_lineno or n.lineno, self.groups, detail=detail))
        return out

    def _is_whole(self, node: ast.AST, fn: FunctionInfo, scope: Scope, whole: set[str]) -> bool:
        """The expression is the whole request body (request.get_json(), request.POST.dict(), ...)."""
        while True:
            if isinstance(node, ast.Await):
                node = node.value
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict" and node.args:
                node = node.args[0]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("dict", "to_dict", "copy")
                and not node.args
            ):
                node = node.func.value
            else:
                break
        if isinstance(node, ast.Name) and node.id in whole:
            return True
        target = node.func if isinstance(node, ast.Call) else node
        if not isinstance(target, (ast.Attribute, ast.Name)):
            return False
        root, attrs = attribute_chain(target)
        if fn.request_param and root == fn.request_param:
            return len(attrs) == 1 and any(attrs[0] in s.whole_body for s in self.matcher.request)
        name = scope.qname(target)
        return bool(name) and any(self.matcher.is_whole_body(s, name) for s in self.matcher.named)

    def _check_cors_wildcard_credentials(self, rule: LogicRule, src: SourceFile, mod: ModuleFacts) -> list[Finding]:
        out = []
        resolver = file_index(src).resolver
        for n in ast.walk(src.tree):
            if not isinstance(n, ast.Call):
                continue
            name = resolver.resolve(n.func) or ""
            kws = {kw.arg: kw.value for kw in n.keywords if kw.arg}
            starlette = name.endswith("CORSMiddleware") or any(
                (resolver.resolve(a) or "").endswith("CORSMiddleware") for a in n.args
            )
            if starlette:
                origins = kws.get("allow_origins")
                regex = kws.get("allow_origin_regex")
                wildcard = (origins is not None and "*" in _strings(origins)) or (
                    regex is not None and any(s in _ALL_ORIGINS for s in _strings(regex))
                )
                if wildcard and _is_true(kws.get("allow_credentials")):
                    out.append(make_finding(rule, src, n.lineno, n.end_lineno or n.lineno, self.groups,
                                            detail="CORSMiddleware: allow_origins=['*'] with allow_credentials=True."))  # fmt: skip
            elif name in ("flask_cors.CORS", "flask_cors.cross_origin", "flask_cors.extension.CORS", "flask_cors.decorator.cross_origin"):
                if not _is_true(kws.get("supports_credentials")):
                    continue
                origins = kws.get("origins")
                resources = kws.get("resources")
                if origins is not None:
                    wildcard = "*" in _strings(origins) or any(s in _ALL_ORIGINS for s in _strings(origins))
                elif resources is not None:
                    wildcard = any(
                        isinstance(k, ast.Constant) and k.value == "origins" and "*" in _strings(v)
                        for d in ast.walk(resources) if isinstance(d, ast.Dict)
                        for k, v in zip(d.keys, d.values)
                    )  # fmt: skip
                else:
                    wildcard = True  # Flask-CORS allows every origin by default
                if wildcard:
                    out.append(make_finding(rule, src, n.lineno, n.end_lineno or n.lineno, self.groups,
                                            detail="Flask-CORS: every origin allowed with supports_credentials=True."))  # fmt: skip
        values = _module_assignment_nodes(src.tree)
        allow_all = values.get("CORS_ALLOW_ALL_ORIGINS") or values.get("CORS_ORIGIN_ALLOW_ALL")
        creds = values.get("CORS_ALLOW_CREDENTIALS")
        if allow_all is not None and creds is not None and _is_true(allow_all.value) and _is_true(creds.value):
            out.append(make_finding(rule, src, allow_all.lineno, allow_all.lineno, self.groups,
                                    detail="django-cors-headers: CORS_ALLOW_ALL_ORIGINS with CORS_ALLOW_CREDENTIALS."))  # fmt: skip
        return out

    def _check_drf_open_viewset(self, rule: LogicRule, src: SourceFile, mod: ModuleFacts) -> list[Finding]:
        out = []
        resolver = file_index(src).resolver
        for cls in mod.classes:
            if not any(b.startswith("rest_framework") or _VIEWSET_BASE.search(b) for b in cls.bases):
                continue
            methods = _method_names(cls)
            writable = any(_WRITABLE_BASE.search(b.rsplit(".", 1)[-1]) for b in cls.bases) or any(
                m in methods for m in _WRITE_ACTIONS
            )
            if not writable or "get_permissions" in methods:
                continue
            if self._class_auth(cls, resolver) or self.project.django_login_middleware:
                continue
            perms = cls.attrs.get("permission_classes")
            if perms is not None:
                why = "permission_classes allows anyone (AllowAny)"
            elif self.project.drf_default == "open":
                why = "no permission_classes, and the project's settings set no DEFAULT_PERMISSION_CLASSES (DRF then allows anyone)"
            else:
                continue  # the default is unknown (no settings file in the scan) or closed
            line = cls.node.lineno
            out.append(make_finding(rule, src, cls.line_start, line, self.groups, detail=f"{cls.name}: {why}."))
        return out

    def _at_def(self, rule: LogicRule, src: SourceFile, fn: FunctionInfo, detail: str) -> Finding:
        return make_finding(rule, src, fn.line_start, fn.line, self.groups, detail=detail)


# --- small AST helpers ---


def _walk_body(node: ast.AST):
    """Every node inside a function's body, without nested functions and classes."""
    stack = list(reversed(getattr(node, "body", [])))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))


def _all_args(node) -> list[ast.arg]:
    a = node.args
    return [*a.posonlyargs, *a.args, *a.kwonlyargs, *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])]


def _text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _has_status(call: ast.Call, codes: tuple[int, ...]) -> bool:
    """abort(403), HTTPException(status_code=401), Response(status=403)."""
    values = [*call.args, *(kw.value for kw in call.keywords if kw.arg in ("status_code", "status", "code"))]
    return any(isinstance(v, ast.Constant) and type(v.value) is int and v.value in codes for v in values)


def _uses_names(node: ast.AST, names: list[str]) -> bool:
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(node))


def _touches(call: ast.Call, names: set[str]) -> bool:
    if isinstance(call.func, ast.Attribute) and call.func.attr == "save":
        root, _ = attribute_chain(call.func.value)
        if root in names:
            return True
    return any(_uses_names(a, list(names)) for a in [*call.args, *(kw.value for kw in call.keywords)])


def _strings(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _class_names(node: ast.AST, resolver) -> list[str]:
    items = node.elts if isinstance(node, (ast.List, ast.Tuple, ast.Set)) else [node]
    return [resolver.resolve(e) or _text(e) for e in items]


def _method_names(cls: ClassInfo) -> set[str]:
    return {n.name for n in cls.node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _module_assignment_nodes(tree: ast.Module) -> dict[str, ast.Assign]:
    out: dict[str, ast.Assign] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = stmt
    return out


def _module_assignments(tree: ast.Module) -> dict[str, ast.expr]:
    return {k: v.value for k, v in _module_assignment_nodes(tree).items()}


def check_logic(
    sources: list[SourceFile], project: ProjectFacts, book: Rulebook, groups: CweGroups
) -> tuple[list[Finding], list[str]]:
    """Run every logic rule over every file. Returns (findings, problems); a file that makes a check
    fail becomes a problem message instead of stopping the other files."""
    checker = LogicChecker(book, groups, project, {s.rel: s for s in sources})
    findings: list[Finding] = []
    problems: list[str] = []
    for src in sources:
        mod = project.get(src.rel)
        if mod is None:
            continue
        try:
            findings += checker.check_file(src, mod)
        except RecursionError:
            problems.append(f"{src.rel}: too deeply nested; logic checks skipped")
        except Exception as exc:  # a bug in one check must not stop the scan
            problems.append(f"{src.rel}: logic checks failed ({type(exc).__name__}: {exc})")
    return findings, problems
