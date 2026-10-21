"""Logic-flaw rules (rules/logic_flaws.yaml): they fire on clear evidence and stay quiet otherwise."""

import ast
import textwrap

from codeguard.reader import read_project
from codeguard.rulechecks.loader import get_rulebook
from codeguard.rulechecks.logic import check_logic
from codeguard.rulechecks.source import SourceFile, SourceSet


def only(found, rule_id):
    return [f for f in found if f[0] == rule_id]


def logic(files: dict[str, str], groups):
    srcs = []
    for rel, code in files.items():
        code = textwrap.dedent(code)
        srcs.append(SourceFile(rel=rel, text=code, tree=ast.parse(code), lines=code.splitlines()))
    book = get_rulebook()
    findings, problems = check_logic(srcs, read_project(SourceSet(python=srcs), book.taint), book, groups)
    assert problems == []
    return sorted((f.evidence.rule_ids[0], f.file, f.line_start) for f in findings)


FLASK_HEAD = """
from flask import Flask, abort, request, session
from flask_login import current_user, login_required
app = Flask(__name__)
"""


def test_delete_without_login_is_reported_but_public_routes_are_not(groups):
    found = logic(
        {
            "app.py": FLASK_HEAD
            + """
@app.route("/login", methods=["POST"])
def login():
    db.session.add(Session())
    db.session.commit()

@app.route("/items/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    db.session.delete(Item.query.get(item_id))
    db.session.commit()

@app.route("/items")
def list_items():
    return "..."
"""
        },
        groups,
    )
    assert found == [("CG-LGC-001", "app.py", 11)]


def test_writes_are_reported_only_when_other_routes_need_a_login(groups):
    unprotected_app = FLASK_HEAD + """
@app.route("/notes", methods=["POST"])
def add_note():
    db.session.add(Note(text=request.form["text"]))
    db.session.commit()
"""
    assert logic({"app.py": unprotected_app}, groups) == []  # a fully public app: unclear, stay quiet
    mixed_app = unprotected_app + """
@app.route("/profile", methods=["POST"])
@login_required
def profile():
    current_user.name = request.form["name"]
    db.session.commit()
"""
    assert logic({"app.py": mixed_app}, groups) == [("CG-LGC-001", "app.py", 6)]


def test_any_login_signal_keeps_the_rule_quiet(groups):
    found = logic(
        {
            "app.py": FLASK_HEAD
            + """
@app.route("/a/<int:id>", methods=["DELETE"])
def a(id):
    if "user_id" not in session:
        abort(401)
    Item.query.get(id).delete()

@app.route("/b/<int:id>", methods=["DELETE"])
def b(id):
    token = request.headers.get("Authorization")
    check(token)
    Item.query.get(id).delete()
"""
        },
        groups,
    )
    assert only(found, "CG-LGC-001") == []  # (deleting any item by id is still reported as IDOR, CG-LGC-003)


def test_before_request_guard_protects_every_flask_route(groups):
    found = logic(
        {
            "app.py": FLASK_HEAD
            + """
@app.before_request
def require_login():
    if not current_user.is_authenticated:
        abort(401)

@app.route("/items/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    db.session.delete(Item.query.get(item_id))
"""
        },
        groups,
    )
    assert only(found, "CG-LGC-001") == []


def test_fastapi_dependencies(groups):
    code = """
from fastapi import APIRouter, Depends, FastAPI
app = FastAPI()

def get_db(): ...
def get_current_user(): ...

@app.delete("/todos/{todo_id}")
def remove(todo_id: int, db=Depends(get_db)):
    db.query(Todo).filter(Todo.id == todo_id).delete()

@app.delete("/done/{todo_id}")
def remove_done(todo_id: int, db=Depends(get_db), user=Depends(get_current_user)):
    db.query(Todo).filter(Todo.id == todo_id, Todo.owner_id == user.id).delete()
"""
    assert logic({"api.py": code}, groups) == [("CG-LGC-001", "api.py", 8)]  # get_db is not a login
    guarded = code.replace("app = FastAPI()", "app = FastAPI(dependencies=[Depends(get_current_user)])")
    found = logic({"api.py": guarded}, groups)
    assert only(found, "CG-LGC-001") == []
    assert found == [("CG-LGC-003", "api.py", 10)]  # logged in, but any user's todo can be deleted


def test_admin_route_with_login_but_no_role(groups):
    found = logic(
        {
            "app.py": FLASK_HEAD
            + """
@app.route("/admin/stats")
@login_required
def admin_stats():
    return "..."

@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role != "admin":
        abort(403)
    return "..."
"""
        },
        groups,
    )
    assert found == [("CG-LGC-002", "app.py", 6)]


def test_idor_is_quiet_with_an_ownership_check(groups):
    code = FLASK_HEAD + """
@app.route("/orders/<int:order_id>")
@login_required
def order(order_id):
    o = Order.query.get_or_404(order_id)
    return o.total

@app.route("/mine/<int:order_id>")
@login_required
def mine(order_id):
    o = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    return o.total

@app.route("/checked/<int:order_id>")
@login_required
def checked(order_id):
    o = Order.query.get_or_404(order_id)
    if o.owner != current_user:
        abort(404)
    return o.total
"""
    assert logic({"app.py": code}, groups) == [("CG-LGC-003", "app.py", 9)]


def test_django_class_views_and_mixins(groups):
    found = logic(
        {
            "views.py": """
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View

class DeleteNote(View):
    def post(self, request, pk):
        Note.objects.filter(pk=pk).delete()

class DeleteMine(LoginRequiredMixin, View):
    def post(self, request, pk):
        Note.objects.filter(pk=pk, owner=request.user).delete()
"""
        },
        groups,
    )
    assert found == [("CG-LGC-001", "views.py", 6)]


def test_drf_viewset_uses_the_project_settings(groups):
    views = """
from rest_framework import viewsets
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
"""
    assert logic({"shop/views.py": views}, groups) == []  # no settings scanned: the default is unknown
    open_settings = 'INSTALLED_APPS = ["rest_framework"]\n'
    assert logic({"shop/views.py": views, "shop/settings.py": open_settings}, groups) == [("CG-LGC-010", "shop/views.py", 3)]
    closed = open_settings + 'REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}\n'
    assert logic({"shop/views.py": views, "shop/settings.py": closed}, groups) == []


def test_upload_checks(groups):
    found = logic(
        {
            "up.py": """
from fastapi import FastAPI, UploadFile
from flask import Flask, request
app = FastAPI()
web = Flask(__name__)

@app.post("/avatar")
async def avatar(file: UploadFile):
    data = await file.read()
    with open(f"static/{file.filename}", "wb") as out:
        out.write(data)

@app.post("/doc")
async def doc(file: UploadFile):
    if file.content_type not in ("application/pdf",):
        raise ValueError("pdf only")
    with open("docs/latest.pdf", "wb") as out:
        out.write(await file.read())

@web.route("/many", methods=["POST"])
def many():
    for f in request.files.getlist("files"):
        f.save("/tmp/" + f.filename)
"""
        },
        groups,
    )
    assert found == [("CG-LGC-004", "up.py", 11), ("CG-LGC-004", "up.py", 23)]


def test_mass_assignment_variants(groups):
    found = logic(
        {
            "views.py": """
from django.http import JsonResponse
from flask import request as flask_request

def create(request):
    Note.objects.create(**request.POST.dict())

def update(request, pk):
    note = Note.objects.get(pk=pk)
    for key, value in request.POST.items():
        setattr(note, key, value)

def fine(request):
    data = request.POST
    Note.objects.create(title=data["title"])
"""
        },
        groups,
    )
    assert found == [("CG-LGC-006", "views.py", 6), ("CG-LGC-006", "views.py", 11)]


def test_cors_variants(groups):
    found = logic(
        {
            "app.py": """
from flask import Flask
from flask_cors import CORS
from fastapi.middleware.cors import CORSMiddleware
app = Flask(__name__)
CORS(app, supports_credentials=True)
CORS(app, origins=["https://a.example"], supports_credentials=True)
CORS(app)
""",
            "settings.py": "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n",
        },
        groups,
    )
    assert found == [("CG-LGC-009", "app.py", 6), ("CG-LGC-009", "settings.py", 1)]


def test_cookie_flags(groups):
    found = logic(
        {
            "app.py": """
from flask import Flask, make_response
app = Flask(__name__)
app.config["SESSION_COOKIE_SECURE"] = False
app.config.update(SESSION_COOKIE_HTTPONLY=False)

@app.route("/")
def index():
    resp = make_response("x")
    resp.set_cookie("theme", "dark")
    resp.set_cookie("auth_token", "t", secure=True, httponly=True)
    resp.set_cookie("jwt", "t", secure=SECURE_COOKIES, httponly=True)
    return resp
"""
        },
        groups,
    )
    # theme is not a login cookie; secure=SECURE_COOKIES is unknown, so it is not reported
    assert found == [("CG-LGC-007", "app.py", 4), ("CG-LGC-008", "app.py", 5)]
