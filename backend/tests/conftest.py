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
