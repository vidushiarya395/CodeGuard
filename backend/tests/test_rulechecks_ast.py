"""The AST matcher behind deprecated_apis.yaml and insecure_settings.yaml."""

import ast
import textwrap

from codeguard.rulechecks.pyast import NameResolver, check_ast_rules, name_matches
from codeguard.rulechecks.source import SourceFile


def src(code, rel="app.py"):
    code = textwrap.dedent(code)
    return SourceFile(rel=rel, text=code, tree=ast.parse(code), lines=code.splitlines())


def rule_ids(code, rulebook, groups, rel="app.py"):
    rules = rulebook.deprecated.rules + rulebook.settings.rules
    return sorted({f.evidence.rule_ids[0] for f in check_ast_rules(src(code, rel), rules, groups)})


def test_resolver_follows_imports_and_variables():
    tree = ast.parse(
        textwrap.dedent(
            """
            import yaml as y
            from flask import Flask
            import requests
            app = Flask(__name__)
            s = requests.Session()
            """
        )
    )
    r = NameResolver(tree)
    assert r.resolve(ast.parse("y.load", mode="eval").body) == "yaml.load"
    assert r.resolve(ast.parse("app.run", mode="eval").body) == "flask.Flask().run"
    assert r.resolve(ast.parse("s.get", mode="eval").body) == "requests.Session().get"


def test_glob_treats_brackets_literally():
    assert name_matches("flask.Flask().config[DEBUG]", ["flask.Flask().config[DEBUG]"])
    assert not name_matches("flask.Flask().config[D]", ["flask.Flask().config[DEBUG]"])
    assert name_matches("x.y.check_hostname", ["*.check_hostname"])


def test_aliases_are_resolved(rulebook, groups):
    assert rule_ids("import yaml as y\ny.load(data)\n", rulebook, groups) == ["CG-DEP-004"]
    assert rule_ids("from yaml import load\nload(data)\n", rulebook, groups) == ["CG-DEP-004"]


def test_yaml_safe_loader_positional_is_safe(rulebook, groups):
    assert rule_ids("import yaml\nyaml.load(data, yaml.SafeLoader)\n", rulebook, groups) == []
    assert rule_ids("import yaml\nyaml.load(data, Loader=yaml.FullLoader)\n", rulebook, groups) == ["CG-DEP-004"]


def test_unknown_kwargs_are_not_guessed(rulebook, groups):
    # **opts may contain Loader=SafeLoader; we cannot show it is unsafe, so we do not report it.
    assert rule_ids("import yaml\nyaml.load(data, **opts)\n", rulebook, groups) == []


def test_eval_on_constant_is_fine(rulebook, groups):
    assert rule_ids('eval("1 + 1")\n', rulebook, groups) == []
    assert rule_ids("eval(f'{x} + 1')\n", rulebook, groups) == ["CG-DEP-007"]
    # model.eval() (PyTorch) is a different function.
    assert rule_ids("import torch\nmodel = torch.nn.Linear(2, 2)\nmodel.eval()\n", rulebook, groups) == []


def test_verify_variable_is_not_reported(rulebook, groups):
    assert rule_ids("import requests\nrequests.get(u, verify=check)\n", rulebook, groups) == []
    assert rule_ids("import requests\ns = requests.Session()\ns.post(u, verify=False)\n", rulebook, groups) == [
        "CG-SET-001"
    ]
    assert rule_ids("import requests\ns = requests.Session()\ns.verify = False\n", rulebook, groups) == ["CG-SET-001"]


def test_flask_debug_variants(rulebook, groups):
    base = "from flask import Flask\napp = Flask(__name__)\n"
    assert rule_ids(base + "app.debug = True\n", rulebook, groups) == ["CG-SET-003"]
    assert rule_ids(base + 'app.config["DEBUG"] = True\n', rulebook, groups) == ["CG-SET-003"]
    assert rule_ids(base + "app.config.update(DEBUG=True)\n", rulebook, groups) == ["CG-SET-003"]
    assert rule_ids(base + "app.run(debug=False)\n", rulebook, groups) == []
    # Some other object's run(debug=True) is not Flask.
    assert rule_ids("runner.run(debug=True)\n", rulebook, groups) == []


def test_django_debug_only_in_settings_files(rulebook, groups):
    assert rule_ids("DEBUG = True\n", rulebook, groups, rel="mysite/settings.py") == ["CG-SET-004"]
    assert rule_ids("DEBUG = True\n", rulebook, groups, rel="mysite/settings/dev.py") == ["CG-SET-004"]
    assert rule_ids("DEBUG = True\n", rulebook, groups, rel="tools/script.py") == []


def test_unverified_https_context_monkeypatch(rulebook, groups):
    code = "import ssl\nssl._create_default_https_context = ssl._create_unverified_context\n"
    assert rule_ids(code, rulebook, groups) == ["CG-SET-002"]


def test_cryptography_ecb_and_old_tls(rulebook, groups):
    code = "from cryptography.hazmat.primitives.ciphers import modes\nm = modes.ECB()\n"
    assert rule_ids(code, rulebook, groups) == ["CG-DEP-009"]
    assert rule_ids("from ssl import PROTOCOL_SSLv3\nx = PROTOCOL_SSLv3\n", rulebook, groups) == ["CG-DEP-003"]


def test_jose_and_aiohttp(rulebook, groups):
    code = 'from jose import jwt\njwt.decode(t, k, options={"verify_signature": False})\n'
    assert rule_ids(code, rulebook, groups) == ["CG-SET-005"]
    assert rule_ids("import aiohttp\naiohttp.TCPConnector(ssl=False)\n", rulebook, groups) == ["CG-SET-001"]


def test_finding_points_at_the_call(rulebook, groups):
    findings = check_ast_rules(
        src("import tempfile\n\n\ndef f():\n    return tempfile.mktemp()\n"), rulebook.deprecated.rules, groups
    )
    assert len(findings) == 1
    f = findings[0]
    assert (f.line_start, f.line_end) == (5, 5)
    assert f.evidence.matched_code.strip() == "return tempfile.mktemp()"
    assert f.cwe_group == "insecure-temp-file"
