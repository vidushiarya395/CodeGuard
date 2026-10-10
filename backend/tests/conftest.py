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
