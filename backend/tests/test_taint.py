"""The taint check (detector "taint"): user input followed to a dangerous call, with the path as evidence."""

import ast
import textwrap

import pytest

from codeguard.agents.ai_mistake_finder import TAINT, run_rule_checks
from codeguard.models import Detector, ToolState
from codeguard.reader import read_project
from codeguard.rulechecks.loader import get_rulebook
from codeguard.rulechecks.source import SourceFile, SourceSet
from codeguard.rulechecks.taint import check_taint

from conftest import EXAMPLES, FakeIndex

TAINT_EXAMPLES = EXAMPLES / "taint"
SINK_IDS = [r.id for r in get_rulebook().taint_rules()]


def taint(code, groups, rel="app.py"):
    code = textwrap.dedent(code)
    src = SourceFile(rel=rel, text=code, tree=ast.parse(code), lines=code.splitlines())
    book = get_rulebook()
    facts = read_project(SourceSet(python=[src]), book.taint).get(rel)
    return check_taint(src, facts, book, groups)


def found(findings):
    return sorted((f.evidence.rule_ids[0], f.line_start) for f in findings)


def _all_findings(folder):
    outcomes = run_rule_checks(folder, index=FakeIndex())
    for o in outcomes:
        assert o.run.state == ToolState.OK, (o.run.tool, o.run.message)
        assert not o.run.file_errors, o.run.file_errors
    return [f for o in outcomes for f in o.findings]


def test_every_sink_has_examples():
    assert len(SINK_IDS) >= 10
    for rule_id in SINK_IDS:
        for kind in ("vulnerable", "safe"):
            folder = TAINT_EXAMPLES / rule_id / kind
            files = [p for p in folder.iterdir() if p.is_file()] if folder.is_dir() else []
            assert len(files) == 1, f"{rule_id}: expected exactly one file in {folder}"


@pytest.mark.parametrize("rule_id", SINK_IDS)
def test_vulnerable_example_is_found_with_its_path(rule_id):
    findings = [f for f in _all_findings(TAINT_EXAMPLES / rule_id / "vulnerable") if rule_id in f.evidence.rule_ids]
    assert findings, f"{rule_id} did not fire on its vulnerable example"
    f = findings[0]
    assert f.detectors == [Detector.TAINT]
    assert f.cwe == get_rulebook().rule(rule_id).cwe
    path = next(m for m in f.evidence.messages if m.startswith("Path: "))
    assert "[input" in path and "[sink]" in path
    assert f.evidence.matched_code


@pytest.mark.parametrize("rule_id", SINK_IDS)
def test_safe_example_is_quiet(rule_id):
    # Stricter than needed: no rule check and no taint finding at all.
    findings = _all_findings(TAINT_EXAMPLES / rule_id / "safe")
    assert findings == [], [(f.evidence.rule_ids, f.line_start) for f in findings]


def test_path_shows_every_step(groups):
    (f,) = taint(
        """
        import subprocess
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/ping")
        def ping():
            host = request.args.get("host")
            cmd = "ping -c 1 " + host
            subprocess.run(cmd, shell=True)
        """,
        groups,
    )
    path = next(m for m in f.evidence.messages if m.startswith("Path: "))
    assert path.startswith("Path: line 8: host = request.args.get(\"host\") [input]")
    assert "line 9: cmd = \"ping -c 1 \" + host" in path
    assert path.endswith("line 10: subprocess.run(cmd, shell=True) [sink]")
    assert "Flask request data" in f.evidence.messages[0]


def test_one_hop_into_a_helper(groups):
    findings = taint(
        """
        import os
        from flask import Flask, request
        app = Flask(__name__)

        def run(command):
            os.system(command)

        def quoted(value):
            import shlex
            return shlex.quote(value)

        @app.route("/a")
        def a():
            run("ls " + request.args["dir"])

        @app.route("/b")
        def b():
            run("ls " + quoted(request.args["dir"]))
        """,
        groups,
    )
    assert found(findings) == [("CG-TNT-001", 7)]
    path = next(m for m in findings[0].evidence.messages if m.startswith("Path: "))
    assert path.startswith("Path: line 15:") and "[in run()]" in path


def test_cli_input_counts_for_commands_but_not_for_urls(groups):
    findings = taint(
        """
        import argparse, os, requests

        def main():
            parser = argparse.ArgumentParser()
            parser.add_argument("url")
            args = parser.parse_args()
            requests.get(args.url, timeout=10)
            os.system("curl " + args.url)
        """,
        groups,
    )
    assert found(findings) == [("CG-TNT-001", 9)]  # SSRF is a server problem; a CLI user may fetch any URL


def test_sanitizer_only_clears_its_own_kind_of_problem(groups):
    findings = taint(
        """
        import html, os
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/x")
        def x():
            name = html.escape(request.args["n"])
            os.system("echo " + name)
            count = int(request.args["c"])
            os.system("seq %d" % count)
        """,
        groups,
    )
    assert found(findings) == [("CG-TNT-001", 9)]  # html.escape does not make a shell command safe; int() does


def test_validation_guard_stops_the_taint(groups):
    findings = taint(
        """
        import os, re
        from flask import Flask, abort, request
        app = Flask(__name__)
        ACTIONS = {"start", "stop"}

        @app.route("/svc")
        def svc():
            action = request.args["action"]
            if action not in ACTIONS:
                abort(400)
            os.system("systemctl " + action)

        @app.route("/svc2")
        def svc2():
            name = request.args["name"]
            if re.fullmatch(r"[a-z]+", name):
                os.system("systemctl restart " + name)
            os.system("echo " + name)
        """,
        groups,
    )
    assert found(findings) == [("CG-TNT-001", 19)]  # only the use outside the validated branch


def test_parameterized_query_is_safe_but_built_query_is_not(groups):
    findings = taint(
        """
        def find(cursor):
            name = input("name: ")
            cursor.execute("SELECT * FROM t WHERE n = ?", (name,))
            cursor.execute("SELECT * FROM t WHERE n = '%s'" % name)
        """,
        groups,
    )
    assert found(findings) == [("CG-TNT-003", 5)]


def test_reassigning_a_clean_value_clears_the_variable(groups):
    findings = taint(
        """
        import os, sys
        cmd = sys.argv[1]
        cmd = "ls"
        os.system(cmd)
        """,
        groups,
    )
    assert findings == []


def test_unknown_calls_do_not_carry_input(groups):
    # db.get(Post, post_id) is a stored object, not the user's text: deleting its file is not path traversal.
    findings = taint(
        """
        import os
        from flask import Flask
        app = Flask(__name__)

        @app.route("/posts/<int:post_id>/image", methods=["DELETE"])
        def drop(post_id):
            post = db.get(Post, post_id)
            os.remove(post.image_path)
        """,
        groups,
    )
    assert findings == []


def test_fastapi_dependencies_are_not_input(groups):
    findings = taint(
        """
        from fastapi import Depends, FastAPI
        app = FastAPI()

        def settings():
            ...

        @app.get("/run")
        def run(cmd: str, cfg=Depends(settings)):
            eval(cfg.expr)
            eval(cmd)
        """,
        groups,
    )
    assert found(findings) == [("CG-TNT-002", 11)]


def test_django_request_parameter(groups):
    findings = taint(
        """
        from django.db import connection
        from django.http import HttpResponse

        def search(request):
            q = request.GET.get("q", "")
            with connection.cursor() as cur:
                cur.execute("SELECT * FROM notes WHERE title LIKE '%" + q + "%'")
            return HttpResponse(f"<p>{q}</p>")
        """,
        groups,
    )
    assert found(findings) == [("CG-TNT-003", 8), ("CG-TNT-009", 9)]


def test_taint_runs_as_its_own_tool(tmp_path):
    (tmp_path / "app.py").write_text("import os, sys\nos.system('ls ' + sys.argv[1])\n", encoding="utf-8")
    outcomes = {o.run.tool: o for o in run_rule_checks(tmp_path, index=FakeIndex())}
    run = outcomes[TAINT]
    assert run.run.state == ToolState.OK and run.run.findings_count == 1
    assert run.findings[0].detectors == [Detector.TAINT]
