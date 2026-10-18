"""Secret checks. Token-like test values are built at run time so the repository never contains them."""

import ast
import textwrap

import pytest

from codeguard.rulechecks.secrets import SecretMatcher, check_secrets, mask, normalize_name
from codeguard.rulechecks.source import SourceFile


def src(code):
    code = textwrap.dedent(code)
    try:
        tree = ast.parse(code)
    except SyntaxError:
        tree = None
    return SourceFile(rel="app.py", text=code, tree=tree, lines=code.splitlines())


@pytest.fixture
def matcher(rulebook):
    return SecretMatcher(rulebook.secrets)


def found(code, rulebook, groups):
    return [(f.evidence.rule_ids[0], f.line_start) for f in check_secrets(src(code), rulebook.secrets, groups)]


@pytest.mark.parametrize(
    "name, expected",
    [("apiKey", "api_key"), ("X-Api-Key", "x_api_key"), ("DB_PASSWORD", "db_password"), ("clientSecret", "client_secret")],
)
def test_normalize_name(name, expected):
    assert normalize_name(name) == expected


@pytest.mark.parametrize(
    "name", ["password", "DB_PASSWORD", "apiKey", "api_key", "SECRET_KEY", "client_secret", "access_token", "pwd"]
)
def test_secret_names(matcher, name):
    assert matcher.is_secret_name(name)


@pytest.mark.parametrize(
    "name",
    ["password_field", "token_url", "API_KEY_ENV", "is_password_valid", "tokenizer", "max_tokens", "eos_token",
     "pad_token", "keyboard", "monkey", "secretary_name", "username"],
)  # fmt: skip
def test_not_secret_names(matcher, name):
    assert not matcher.is_secret_name(name)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Tr0ub4dor-prod-42", "CG-SEC-002"),
        ("YOUR_API_KEY_HERE", "CG-SEC-003"),
        ("<your-token>", "CG-SEC-003"),
        ("changeme", "CG-SEC-003"),
        ("dev-secret-key", "CG-SEC-003"),
        ("sk-...", "CG-SEC-003"),
        ("xxxxxxxx", "CG-SEC-003"),
        ("", None),
        ("OPENAI_API_KEY", None),  # an environment variable's name, not a secret
        ("Bearer {}", None),  # a template
        ("abc", None),  # too short to judge
        ("Please type your password", None),  # a sentence
    ],
)
def test_classify(matcher, value, expected):
    assert matcher.classify("api_key", value) == expected


def _token_samples():
    # Built from pieces so that no complete token-shaped string is stored in the repository.
    a, z = "A" * 16, "a" * 36
    return {
        "AWS access key ID": "AKIA" + a,
        "GitHub token": "ghp_" + z,
        "GitHub fine-grained token": "github_pat_" + "b" * 82,
        "Slack token": "xoxb-" + "1" * 12 + "-abcdefghij",
        "Stripe live secret key": "sk_" + "live_" + "c" * 24,
        "Google API key": "AIza" + "d" * 35,
        "Private key (PEM)": "-----BEGIN RSA " + "PRIVATE KEY-----",
    }


def test_every_token_pattern_has_a_sample(rulebook):
    assert {p.name for p in rulebook.secrets.token_patterns} == set(_token_samples())


@pytest.mark.parametrize("name, token", list(_token_samples().items()))
def test_token_patterns(rulebook, groups, name, token):
    findings = check_secrets(src(f"# config\nvalue = {token!r}\n"), rulebook.secrets, groups)
    assert [f.evidence.rule_ids[0] for f in findings] == ["CG-SEC-001"]
    assert findings[0].title == f"Hard-coded {name}"
    assert findings[0].line_start == 2
    assert token not in findings[0].evidence.matched_code  # masked


def test_token_in_comment_and_broken_file(rulebook, groups):
    token = "ghp_" + "e" * 36
    # Not valid Python, but text checks still run.
    assert found(f"def broken(:\n    # token: {token}\n", rulebook, groups) == [("CG-SEC-001", 2)]


def test_places_secrets_are_found(rulebook, groups):
    code = '''
    import os
    password = "hunter2-real"
    cfg = {"api_key": "q8w7e6r5t4y3"}
    connect(user="u", password="s3cr3t-pass")
    settings["SECRET_KEY"] = "abcd1234efgh"
    if password == "letmein":
        pass
    TOKEN = os.getenv("API_TOKEN", "your-token-here")
    '''
    assert found(code, rulebook, groups) == [
        ("CG-SEC-002", 3),
        ("CG-SEC-002", 4),
        ("CG-SEC-002", 5),
        ("CG-SEC-002", 6),
        ("CG-SEC-003", 7),
        ("CG-SEC-003", 9),
    ]


def test_evidence_is_masked(rulebook, groups):
    f = check_secrets(src('DB_PASSWORD = "Tr0ub4dor-prod-42"\n'), rulebook.secrets, groups)[0]
    assert "Tr0ub4dor-prod-42" not in f.evidence.matched_code
    assert "Tr0ub4dor-prod-42" not in " ".join(f.evidence.messages)
    assert f.evidence.matched_code.startswith('DB_PASSWORD = "Tr0u')


def test_mask():
    assert mask("abcdefghijkl") == "abcd********"
    assert mask("abcdef") == "ab****"


def test_real_world_false_alarms_stay_fixed(matcher):
    # Found by scanning popular libraries: an enum label and a "-" (stdin) marker are not secrets.
    assert matcher.classify("apiKey", "apiKey") is None
    assert matcher.classify("password", "-") is None


@pytest.mark.parametrize(
    "code",
    [
        'url = replace(password="********")\n',  # redaction mask (starlette)
        'headers["Access-Control-Allow-Credentials"] = "true"\n',  # a boolean written as text
        "if token == 'root':\n    pass\n",  # a lexer token, not a credential (pygments)
        'token = r"[-!#$%&\'*+.^_`|~0-9a-zA-Z]+"\n',  # a regular expression (h11)
        "jsonnet_token = r'[^\W\d]\w*'\n",  # a regular expression (pygments)
    ],
)
def test_more_real_world_false_alarms(rulebook, groups, code):
    assert found(code, rulebook, groups) == []


def test_password_comparison_is_still_found(rulebook, groups):
    assert found('if password == "s3cret-admin":\n    pass\n', rulebook, groups) == [("CG-SEC-002", 1)]
