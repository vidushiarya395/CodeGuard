from __future__ import annotations

from pathlib import Path

import pytest

from codeguard.config import Settings
from codeguard.cwe import CweGroups, get_cwe_groups
from codeguard.scanners.bandit import find_bandit
from codeguard.scanners.semgrep import find_semgrep

# The example files are scanned, never imported or run, so pytest must not collect them.
collect_ignore = ["examples"]

TESTS_DIR = Path(__file__).parent
EXAMPLES = TESTS_DIR / "examples"
FIXTURES = TESTS_DIR / "fixtures"


@pytest.fixture
def examples_dir() -> Path:
    return EXAMPLES


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def groups() -> CweGroups:
    return get_cwe_groups()


@pytest.fixture
def settings() -> Settings:
    return Settings()


requires_semgrep = pytest.mark.skipif(find_semgrep(Settings()) is None, reason="Semgrep is not installed")
requires_bandit = pytest.mark.skipif(find_bandit() is None, reason="Bandit is not installed")


# --- A fake PyPI / OSV, so tests never use the network ---

from codeguard.rulechecks.netclient import NetworkDown, canonical_name  # noqa: E402

KNOWN_PACKAGES = {
    "requests", "opencv-python", "pyyaml", "flask", "paramiko", "pyjwt", "pycryptodome",
    "jinja2", "boto3", "psycopg2",
    # web frameworks used by the logic-flaw and taint examples
    "django", "djangorestframework", "django-cors-headers", "fastapi", "starlette", "pydantic",
    "sqlalchemy", "flask-login", "flask-sqlalchemy", "flask-wtf", "flask-cors", "werkzeug",
    "markupsafe", "click",
}  # fmt: skip
FAKE_ADVISORY = {"id": "GHSA-test-0001", "summary": "Example advisory (test data)", "aliases": ["CVE-2000-0001"]}


class FakeIndex:
    """Answers like PyPI and OSV would, from fixed test data."""

    def __init__(self, known=KNOWN_PACKAGES, vulnerable=None, down=False):
        self.known = {canonical_name(k) for k in known}
        self.vulnerable = vulnerable if vulnerable is not None else {("flask", "0.12"): [FAKE_ADVISORY]}
        self.down = down
        self.calls: list[tuple] = []

    def pypi_exists(self, name):
        self.calls.append(("pypi", name))
        if self.down:
            raise NetworkDown("could not reach pypi.org (test: network off)")
        return canonical_name(name) in self.known

    def osv_vulns(self, name, version):
        self.calls.append(("osv", name, version))
        if self.down:
            raise NetworkDown("could not reach api.osv.dev (test: network off)")
        return list(self.vulnerable.get((canonical_name(name), version), []))


@pytest.fixture
def fake_index() -> FakeIndex:
    return FakeIndex()


@pytest.fixture
def rulebook():
    from codeguard.rulechecks.loader import get_rulebook

    return get_rulebook()


# --- A fake AI provider, so tests never call a real AI API ---

import json  # noqa: E402
import re  # noqa: E402

from codeguard.llm.base import LLMUnavailable, ProviderReply  # noqa: E402
from codeguard.llm.checklist import get_checklist  # noqa: E402
from codeguard.llm.client import LLMClient, RateLimiter  # noqa: E402


@pytest.fixture(autouse=True)
def no_real_ai(monkeypatch):
    """Every test: real AI HTTP calls fail loudly, and scans get no AI client unless a test gives one.
    So a real GEMINI_API_KEY / GROQ_API_KEY in .env is never used by the tests."""

    def blocked(*args, **kwargs):
        raise AssertionError("a test tried to call a real AI API")

    def no_client(settings=None):
        raise LLMUnavailable("AI review is off in tests (tests never call real AI APIs)")

    monkeypatch.setattr("codeguard.llm.providers.http_post", blocked)
    monkeypatch.setattr("codeguard.agents.llm_review.make_client", no_client)
    monkeypatch.setattr("codeguard.llm.make_client", no_client)
    monkeypatch.setattr("codeguard.llm.client.make_client", no_client)


class FakeProvider:
    """Answers from a function (system, user) -> text, or from a list of texts / exceptions."""

    name = "fake"
    default_rpm = 0
    default_rpd = 0

    def __init__(self, respond, model: str = "fake-model"):
        self.model = model
        self.respond = respond
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> ProviderReply:
        self.calls.append((system, user))
        out = self.respond(system, user) if callable(self.respond) else self.respond.pop(0)
        if isinstance(out, Exception):
            raise out
        return ProviderReply(text=out, model_version=f"{self.model}-001")


@pytest.fixture
def make_llm(tmp_path):
    """make_llm(respond) -> an LLMClient around a FakeProvider, with no waiting and no limits."""

    def make(respond, model: str = "fake-model", **kwargs) -> LLMClient:
        kwargs.setdefault("limiter", RateLimiter(0, 0, None, "fake"))
        kwargs.setdefault("sleep", lambda s: None)
        return LLMClient(FakeProvider(respond, model), tmp_path / "cache", **kwargs)

    return make


CHECKLIST_IDS = [item.id for item in get_checklist().items]
_CODE_LINE = re.compile(r"^\s*(\d+) \| (.*)$")


def prompt_code(user: str) -> dict[int, str]:
    """The numbered code lines inside the markers of a prompt: {line number: code}."""
    start = user.index("<<<CODE ")
    boundary = user[start:].split()[1]
    end = user.index(f"CODE {boundary}>>>")
    block = user[start:end].splitlines()[1:]
    return {int(m.group(1)): m.group(2) for m in map(_CODE_LINE.match, block) if m}


# What an honest reviewer looks for: (checklist item, text on the line).
HONEST_SIGNS = [("CG-CHK-003", "eval("), ("CG-CHK-002", 'execute(f"'), ("CG-CHK-001", "shell=True")]


def honest_reviewer(system: str, user: str) -> str:
    """A fake model that reviews the code itself and never follows text inside it."""
    code = prompt_code(user)
    if user.startswith("Task: is anything else"):
        return json.dumps({"issues": []})
    answers = []
    for cid in CHECKLIST_IDS:
        lines = [n for n, text in code.items() for sid, sign in HONEST_SIGNS if sid == cid and sign in text]
        answers.append(
            {"id": cid, "answer": "yes" if lines else "no", "lines": lines, "reason": "found in code" if lines else "not present"}
        )
    return json.dumps({"answers": answers})


def checklist_json(yes: dict | None = None, skip: tuple = ()) -> str:
    """A checklist answer: every item "no", except those in `yes` ({id: [lines]})."""
    yes = yes or {}
    return json.dumps(
        {
            "answers": [
                {"id": cid, "answer": "yes" if cid in yes else "no", "lines": yes.get(cid, []), "reason": f"reason {cid}"}
                for cid in CHECKLIST_IDS
                if cid not in skip
            ]
        }
    )
