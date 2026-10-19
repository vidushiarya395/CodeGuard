"""The AI layer: one LLMClient for Gemini (default), Groq and Ollama."""

from codeguard.llm.base import (
    InvalidAnswer,
    LLMAuthError,
    LLMError,
    LLMUnavailable,
    Provider,
    ProviderReply,
    QuotaExhausted,
)
from codeguard.llm.client import LLMClient, LLMResult, Prompt, RateLimiter, make_client

__all__ = [
    "InvalidAnswer",
    "LLMAuthError",
    "LLMClient",
    "LLMError",
    "LLMResult",
    "LLMUnavailable",
    "Prompt",
    "Provider",
    "ProviderReply",
    "QuotaExhausted",
    "RateLimiter",
    "make_client",
]
