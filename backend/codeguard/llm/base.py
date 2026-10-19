"""Shared types for the AI layer: what a provider must do, and the errors it can raise."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

# Every provider is asked for the same thing: deterministic (temperature 0, fixed seed) JSON.
TEMPERATURE = 0
SEED = 42


@dataclass(frozen=True)
class ProviderReply:
    text: str
    # The exact model version the provider reports, when it reports one (e.g. Gemini's modelVersion).
    model_version: str | None = None


class Provider(Protocol):
    name: str  # "gemini", "groq", "ollama"
    model: str
    default_rpm: int  # requests per minute allowed on the free tier (0 = no limit)
    default_rpd: int  # requests per day allowed on the free tier (0 = no limit)

    def complete(self, system: str, user: str) -> ProviderReply: ...


class LLMError(Exception):
    """Base class for everything that can go wrong when asking the AI."""


class LLMUnavailable(LLMError):
    """The provider cannot be used at all (no API key set, Ollama not running, unknown provider)."""


class LLMAuthError(LLMError):
    """The provider rejected the API key."""


class RateLimited(LLMError):
    """HTTP 429. Retried after a wait, unless the daily quota is used up."""

    def __init__(self, message: str, retry_after: float | None = None, daily: bool = False):
        super().__init__(message)
        self.retry_after = retry_after
        self.daily = daily


class QuotaExhausted(LLMError):
    """The free daily limit is used up. Stop asking until tomorrow."""


class TransientError(LLMError):
    """A temporary problem (server error, timeout, network). Retried with backoff."""


class PermanentError(LLMError):
    """A problem retrying will not fix (bad request, blocked prompt)."""


class InvalidAnswer(LLMError):
    """The AI answered, but the answer was not valid JSON or did not pass validation."""
