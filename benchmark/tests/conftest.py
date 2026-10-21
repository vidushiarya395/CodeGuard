from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codeguard.llm.base import ProviderReply
from codeguard.llm.client import LLMClient, RateLimiter

# Make `import benchmark` work however pytest is started.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class FakeProvider:
    """Answers from a list of texts; tests never call a real AI API."""

    name = "fake"
    default_rpm = 0
    default_rpd = 0

    def __init__(self, answers: list, model: str = "fake-model"):
        self.model = model
        self.answers = list(answers)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> ProviderReply:
        self.calls.append((system, user))
        out = self.answers.pop(0)
        if isinstance(out, Exception):
            raise out
        return ProviderReply(text=out, model_version=f"{self.model}-001")


@pytest.fixture
def make_llm(tmp_path):
    def make(answers: list) -> LLMClient:
        return LLMClient(
            FakeProvider(answers), tmp_path / "cache", limiter=RateLimiter(0, 0, None, "fake"), sleep=lambda s: None
        )

    return make
