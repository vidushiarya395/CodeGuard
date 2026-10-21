"""The Code Reader: functions, routes, decorators and entry points, read with ast only."""

import ast
import textwrap

from codeguard.reader import read_project
from codeguard.rulechecks.loader import get_rulebook
from codeguard.rulechecks.source import SourceFile, SourceSet, load_sources


def project(files: dict[str, str]):
    srcs = []
    for rel, code in files.items():
        code = textwrap.dedent(code)
        try:
            tree = ast.parse(code)
        except SyntaxError:
            tree = None
        srcs.append(SourceFile(rel=rel, text=code, tree=tree, lines=code.splitlines()))
    return read_project(SourceSet(python=srcs), get_rulebook().taint)


def fn(facts, rel, name):
    return facts.get(rel).function(name)


def test_flask_routes_methods_decorators_and_inputs():
    p = project(
        {
            "app.py": """
            from flask import Blueprint, Flask, request
            from flask_login import login_required as needs_login

            app = Flask(__name__)
            bp = Blueprint("posts", __name__)

            @app.route("/posts/<int:post_id>", methods=["GET", "POST"])
            @needs_login
            def edit(post_id):
                title = request.form["title"]
                return title

            @bp.delete("/posts/<int:post_id>")
            def remove(post_id):
                ...
            """
        }
    )
    edit = fn(p, "app.py", "edit")
    assert edit.framework == "flask"
    assert edit.methods == {"GET", "POST"} and edit.paths == ["/posts/<int:post_id>"]
    assert edit.decorators == ["flask.Flask().route()", "flask_login.login_required"]
    assert edit.input_params == {"post_id": "route-parameter"}
    assert [(e.kind, e.what, e.line) for e in edit.entry_points] == [
        ("web", "parameter post_id", 10),
        ("web", "flask.request.form", 11),
    ]
    remove = fn(p, "app.py", "remove")
    assert remove.framework == "flask" and remove.methods == {"DELETE"}


def test_fastapi_parameters_dependencies_and_request():
    p = project(
        {
            "api.py": """
            from fastapi import APIRouter, Depends, Request, UploadFile
            from sqlalchemy.orm import Session

            router = APIRouter()

            def get_db(): ...
            def current_user(): ...

            @router.post("/items/{item_id}")
            async def create(item_id: int, q: str, file: UploadFile, request: Request,
                             db: Session = Depends(get_db), user=Depends(current_user)):
                body = await request.json()
                return body
            """
        }
    )
    create = fn(p, "api.py", "create")
    assert create.framework == "fastapi" and create.methods == {"POST"}
    assert set(create.input_params) == {"item_id", "q", "file"}  # not db, user (dependencies) or request
    assert create.depends == ["get_db", "current_user"]
    assert create.request_param == "request"
    assert ("web", "request.json") in [(e.kind, e.what) for e in create.entry_points]


def test_django_views_get_paths_from_urls_in_another_file():
    p = project(
        {
            "notes/views.py": """
            from django.contrib.auth.decorators import login_required
            from django.views import View
            from django.views.decorators.http import require_POST

            @login_required
            @require_POST
            def delete_note(request, pk):
                ...

            class NoteView(View):
                def post(self, request, pk):
                    q = request.POST.get("text")
            """,
            "notes/urls.py": """
            from django.urls import path
            from . import views

            urlpatterns = [
                path("notes/<int:pk>/delete/", views.delete_note),
                path("notes/<int:pk>/", views.NoteView.as_view()),
            ]
            """,
        }
    )
    delete = fn(p, "notes/views.py", "delete_note")
    assert delete.framework == "django" and delete.methods == {"POST"}
    assert delete.paths == ["notes/<int:pk>/delete/"]
    assert delete.input_params == {"pk": "route-parameter"} and delete.request_param == "request"
    post = fn(p, "notes/views.py", "NoteView.post")
    assert post.framework == "django" and post.methods == {"POST"} and post.paths == ["notes/<int:pk>/"]
    assert ("web", "request.POST.get") in [(e.kind, e.what) for e in post.entry_points]


def test_drf_viewset_actions_are_routes():
    p = project(
        {
            "api.py": """
            from rest_framework import viewsets
            from rest_framework.decorators import action

            class AccountViewSet(viewsets.ModelViewSet):
                def destroy(self, request, pk=None):
                    ...

                @action(detail=True, methods=["post"])
                def close(self, request, pk=None):
                    ...

                def helper(self):
                    ...
            """
        }
    )
    assert fn(p, "api.py", "AccountViewSet.destroy").methods == {"DELETE"}
    assert fn(p, "api.py", "AccountViewSet.close").methods == {"POST"}
    assert fn(p, "api.py", "AccountViewSet.helper").framework is None


def test_cli_and_other_entry_points():
    p = project(
        {
            "tool.py": """
            import argparse, os, sys
            import click

            @click.command()
            @click.option("--name")
            def hello(name):
                print(name)

            def main():
                parser = argparse.ArgumentParser()
                args = parser.parse_args()
                key = os.environ.get("KEY")
                data = open(args.path).read()
                answer = input("? ")

            if __name__ == "__main__":
                print(sys.argv[1])
            """
        }
    )
    mod = p.get("tool.py")
    assert fn(p, "tool.py", "hello").input_params == {"name": "command-line"}
    kinds = [(e.kind, e.line) for e in mod.entry_points]
    assert kinds == [("cli", 7), ("cli", 12), ("env", 13), ("file", 14), ("stdin", 15), ("cli", 18)]


def test_unparseable_file_gives_facts_without_crashing():
    p = project({"broken.py": "def f(:\n    pass\n", "ok.py": "x = 1\n"})
    assert p.get("broken.py").parsed is False and p.get("broken.py").functions == []
    assert p.get("ok.py").parsed is True
    assert p.errors == []


def test_reader_reads_the_example_folders(examples_dir):
    sources = load_sources(examples_dir / "rules")
    p = read_project(sources, get_rulebook().taint)
    assert p.errors == []
    assert len(p.modules) == len(sources.python)
